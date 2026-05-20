package repoexposure

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/identrail/identrail/internal/domain"
)

const (
	defaultHistoryLimit = 500
	defaultMaxFindings  = 200
	maxFileSizeBytes    = 1 << 20

	ScanModeDeep  = "deep"
	ScanModeDelta = "delta"
	ScanModeQuick = "quick"
)

var hunkHeaderPattern = regexp.MustCompile(`@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)
var repositorySharedAddressRange = mustParseCIDR("100.64.0.0/10")
var repositoryHostLookupIPs = func(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP != nil {
			ips = append(ips, addr.IP)
		}
	}
	return ips, nil
}

// CommandRunner executes git commands. It is injectable for deterministic tests.
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// EnvCommandRunner executes commands with additional environment variables.
// The extra environment is kept out of command-line arguments so clone
// credentials are not exposed through process arguments or error strings.
type EnvCommandRunner func(ctx context.Context, env []string, name string, args ...string) ([]byte, error)

// HTTPSCloneCredential supplies a temporary credential for HTTPS git clones.
// Password must never be persisted; Scanner only keeps it in memory for the
// duration of one scan.
type HTTPSCloneCredential struct {
	Host     string
	Username string
	Password string
}

// Option customizes scanner behavior.
type Option func(*Scanner)

// Scanner detects secret exposure and misconfiguration findings in Git repositories.
type Scanner struct {
	run             CommandRunner
	runEnv          EnvCommandRunner
	now             func() time.Time
	historyLimit    int
	maxFindings     int
	cloneCredential HTTPSCloneCredential
	adapters        []ExternalFindingAdapter
}

// ScanOptions scopes repository scanning for full backfills, push deltas, and quick HEAD checks.
type ScanOptions struct {
	Mode         string   `json:"mode,omitempty"`
	BaseRevision string   `json:"base_revision,omitempty"`
	HeadRevision string   `json:"head_revision,omitempty"`
	ChangedPaths []string `json:"changed_paths,omitempty"`
}

// ScanResult summarizes one repository exposure scan.
type ScanResult struct {
	Repository     string           `json:"repository"`
	CommitsScanned int              `json:"commits_scanned"`
	FilesScanned   int              `json:"files_scanned"`
	Findings       []domain.Finding `json:"findings"`
	Truncated      bool             `json:"truncated"`
	ScanMode       string           `json:"scan_mode"`
	BaseRevision   string           `json:"base_revision,omitempty"`
	HeadRevision   string           `json:"head_revision,omitempty"`
	ChangedPaths   []string         `json:"changed_paths,omitempty"`
	StartedAt      time.Time        `json:"started_at"`
	CompletedAt    time.Time        `json:"completed_at"`
}

// NewScanner builds a repo exposure scanner with secure defaults.
func NewScanner(runner CommandRunner, options ...Option) *Scanner {
	if runner == nil {
		runner = defaultCommandRunner
	}
	s := &Scanner{
		run:          runner,
		runEnv:       defaultEnvCommandRunner,
		now:          time.Now,
		historyLimit: defaultHistoryLimit,
		maxFindings:  defaultMaxFindings,
	}
	for _, option := range options {
		if option != nil {
			option(s)
		}
	}
	if s.historyLimit < 1 {
		s.historyLimit = defaultHistoryLimit
	}
	if s.maxFindings < 1 {
		s.maxFindings = defaultMaxFindings
	}
	return s
}

// WithEnvCommandRunner overrides command execution that needs extra env vars.
// It is intended for tests and credential-safe git clone execution.
func WithEnvCommandRunner(runner EnvCommandRunner) Option {
	return func(s *Scanner) {
		if runner != nil {
			s.runEnv = runner
		}
	}
}

// WithHistoryLimit limits commit history depth for secret scanning.
func WithHistoryLimit(limit int) Option {
	return func(s *Scanner) {
		s.historyLimit = limit
	}
}

// WithMaxFindings caps finding volume per scan for deterministic output.
func WithMaxFindings(max int) Option {
	return func(s *Scanner) {
		s.maxFindings = max
	}
}

// WithNow overrides time source (tests only).
func WithNow(now func() time.Time) Option {
	return func(s *Scanner) {
		if now != nil {
			s.now = now
		}
	}
}

// WithHTTPSCloneCredential configures a short-lived HTTPS clone credential.
// The credential is used only when the clone target host matches credential.Host.
func WithHTTPSCloneCredential(credential HTTPSCloneCredential) Option {
	return func(s *Scanner) {
		credential.Host = strings.ToLower(strings.TrimSpace(credential.Host))
		credential.Username = strings.TrimSpace(credential.Username)
		credential.Password = strings.TrimSpace(credential.Password)
		s.cloneCredential = credential
	}
}

// ScanRepository performs a full read-only repository exposure scan.
func (s *Scanner) ScanRepository(ctx context.Context, target string) (ScanResult, error) {
	return s.ScanRepositoryWithOptions(ctx, target, ScanOptions{Mode: ScanModeDeep})
}

// ScanRepositoryWithOptions performs read-only scanning for commit-history secret exposure and HEAD misconfigurations.
func (s *Scanner) ScanRepositoryWithOptions(ctx context.Context, target string, options ScanOptions) (ScanResult, error) {
	repo := strings.TrimSpace(target)
	if repo == "" {
		return ScanResult{}, fmt.Errorf("repository target is required")
	}
	options = normalizeScanOptions(options)

	started := s.now().UTC()
	location, cleanup, err := s.prepareRepository(ctx, repo)
	if err != nil {
		return ScanResult{}, err
	}
	defer cleanup()

	headCommit, err := s.resolveRevision(ctx, location, firstNonEmptyScanString(options.HeadRevision, "HEAD"))
	if err != nil {
		return ScanResult{}, err
	}
	shallowExclusionArgs, err := s.shallowBoundaryExclusionArgs(ctx, location)
	if err != nil {
		return ScanResult{}, err
	}
	if options.HeadRevision == "" {
		options.HeadRevision = headCommit
	}
	commits, err := s.listCommitsForOptions(ctx, location, options, shallowExclusionArgs)
	if err != nil {
		return ScanResult{}, err
	}
	changedPaths, err := s.changedPathsForOptions(ctx, location, options)
	if err != nil {
		return ScanResult{}, err
	}
	options.ChangedPaths = changedPaths

	findings := make([]domain.Finding, 0, s.maxFindings)
	seen := map[string]struct{}{}
	truncated := false
	secretPolicy := s.loadSecretFindingPolicy(ctx, location, options.HeadRevision)
	secretOptions := []secretFindingOption{withSecretFindingPolicy(secretPolicy)}

	if options.Mode != ScanModeQuick {
		logArgs := s.historyLogArgs(options, shallowExclusionArgs)
		historyReader, waitLog, logErr := s.gitStream(ctx, location, logArgs...)
		if logErr != nil {
			return ScanResult{}, fmt.Errorf("scan commit history: %w", logErr)
		}
		scanErr := scanHistoryLines(ctx, historyReader, func(added addedLine) bool {
			secretFindings := detectSecretFindings(location.Display, added.Commit, added.Path, added.Line, added.Text, started, secretOptions...)
			for _, finding := range secretFindings {
				if _, exists := seen[finding.ID]; exists {
					continue
				}
				seen[finding.ID] = struct{}{}
				findings = append(findings, finding)
				if len(findings) >= s.maxFindings {
					truncated = true
					return false
				}
			}
			return true
		})
		waitErr := waitLog()
		if ctx.Err() != nil {
			return ScanResult{}, ctx.Err()
		}
		if scanErr != nil && !truncated {
			return ScanResult{}, fmt.Errorf("scan commit history: %w", scanErr)
		}
		if waitErr != nil && !truncated {
			return ScanResult{}, fmt.Errorf("scan commit history: %w", waitErr)
		}
	}

	filesScanned := 0
	if !truncated {
		headFiles, fileErr := s.filesForHeadInspection(ctx, location, options)
		if fileErr != nil {
			return ScanResult{}, fileErr
		}
		for _, filePath := range headFiles {
			if err := ctx.Err(); err != nil {
				return ScanResult{}, err
			}
			if !shouldInspectMisconfiguration(filePath) {
				continue
			}
			content, readErr := s.git(ctx, location, "show", options.HeadRevision+":"+filePath)
			if readErr != nil {
				return ScanResult{}, fmt.Errorf("read %s file %s: %w", options.HeadRevision, filePath, readErr)
			}
			if len(content) == 0 || len(content) > maxFileSizeBytes || !utf8.Valid(content) {
				continue
			}
			filesScanned++
			for _, finding := range detectMisconfigFindings(location.Display, headCommit, filePath, content, started) {
				if _, exists := seen[finding.ID]; exists {
					continue
				}
				seen[finding.ID] = struct{}{}
				findings = append(findings, finding)
				if len(findings) >= s.maxFindings {
					truncated = true
					break
				}
			}
			if truncated {
				break
			}
		}
	}
	if !truncated && len(s.adapters) > 0 {
		for _, adapter := range s.adapters {
			if err := ctx.Err(); err != nil {
				return ScanResult{}, err
			}
			if adapter == nil {
				continue
			}
			adapterFindings, adapterErr := adapter.Findings(ctx, ExternalAdapterInput{
				Repository: location.Display,
				Commit:     headCommit,
				DetectedAt: started,
			})
			if adapterErr != nil {
				return ScanResult{}, fmt.Errorf("run external repo finding adapter %s: %w", adapter.Name(), adapterErr)
			}
			var adapterTruncated bool
			findings, adapterTruncated = appendExternalFindings(findings, adapterFindings, seen, s.maxFindings)
			if adapterTruncated {
				truncated = true
				break
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity == findings[j].Severity {
			if findings[i].Type == findings[j].Type {
				return findings[i].ID < findings[j].ID
			}
			return findings[i].Type < findings[j].Type
		}
		return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
	})

	return ScanResult{
		Repository:     location.Display,
		CommitsScanned: len(commits),
		FilesScanned:   filesScanned,
		Findings:       findings,
		Truncated:      truncated,
		ScanMode:       options.Mode,
		BaseRevision:   options.BaseRevision,
		HeadRevision:   headCommit,
		ChangedPaths:   append([]string(nil), options.ChangedPaths...),
		StartedAt:      started,
		CompletedAt:    s.now().UTC(),
	}, nil
}

type repositoryLocation struct {
	Path    string
	Bare    bool
	Display string
}

type remoteRepositoryRef struct {
	Name string
	SHA  string
}

type remoteRepositoryClonePlan struct {
	DefaultRef   remoteRepositoryRef
	DefaultDepth int
	ExtraRefs    []remoteRepositoryRef
	ExtraDepth   int
}

func (s *Scanner) prepareRepository(ctx context.Context, target string) (repositoryLocation, func(), error) {
	if local, ok := localRepository(target); ok {
		return local, func() {}, nil
	}

	cloneURL := normalizeRepositoryInput(target)
	if err := validateCloneURL(cloneURL); err != nil {
		return repositoryLocation{}, nil, err
	}
	workdir, err := os.MkdirTemp("", "identrail-repo-*")
	if err != nil {
		return repositoryLocation{}, nil, fmt.Errorf("create temp repository directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(workdir) }
	repoPath := filepath.Join(workdir, "repo.git")
	if runErr := s.cloneRemoteRepository(ctx, workdir, cloneURL, repoPath); runErr != nil {
		cleanup()
		return repositoryLocation{}, nil, fmt.Errorf("clone repository: %w", runErr)
	}
	return repositoryLocation{Path: repoPath, Bare: true, Display: target}, cleanup, nil
}

func (s *Scanner) cloneRemoteRepository(ctx context.Context, workdir string, cloneURL string, repoPath string) error {
	runner, cleanup, err := s.cloneCommandRunner(workdir, cloneURL)
	if err != nil {
		return err
	}
	defer cleanup()

	refsOutput, err := runner(ctx, "git", "ls-remote", "--symref", cloneURL)
	if err != nil {
		return fmt.Errorf("list remote refs: %w", err)
	}
	refs, defaultRefName := parseRemoteRepositoryRefs(refsOutput)
	plan, err := buildRemoteRepositoryClonePlan(refs, defaultRefName, s.historyLimit)
	if err != nil {
		return err
	}

	if _, err := runner(ctx, "git", "init", "--bare", "--quiet", repoPath); err != nil {
		return fmt.Errorf("initialize bounded repository clone: %w", err)
	}
	if _, err := runner(ctx, "git", "--git-dir", repoPath, "remote", "add", "origin", cloneURL); err != nil {
		return fmt.Errorf("configure repository remote: %w", err)
	}
	if err := fetchRemoteRepositoryRefs(ctx, runner, repoPath, plan.ExtraRefs, plan.ExtraDepth); err != nil {
		return err
	}
	if err := fetchRemoteRepositoryRefs(ctx, runner, repoPath, []remoteRepositoryRef{plan.DefaultRef}, plan.DefaultDepth); err != nil {
		return err
	}
	if err := pointRemoteRepositoryHead(ctx, runner, repoPath, plan.DefaultRef); err != nil {
		return err
	}
	return nil
}

func pointRemoteRepositoryHead(ctx context.Context, runner CommandRunner, repoPath string, ref remoteRepositoryRef) error {
	if strings.HasPrefix(ref.Name, "refs/heads/") {
		if _, err := runner(ctx, "git", "--git-dir", repoPath, "symbolic-ref", "HEAD", ref.Name); err != nil {
			return fmt.Errorf("point bounded repository clone HEAD at %s: %w", ref.Name, err)
		}
		return nil
	}
	commitOutput, err := runner(ctx, "git", "--git-dir", repoPath, "rev-parse", ref.Name+"^{commit}")
	if err != nil {
		return fmt.Errorf("resolve bounded repository HEAD commit for %s: %w", ref.Name, err)
	}
	commit := strings.TrimSpace(string(commitOutput))
	if commit == "" {
		return fmt.Errorf("resolve bounded repository HEAD commit for %s: empty commit", ref.Name)
	}
	if _, err := runner(ctx, "git", "--git-dir", repoPath, "update-ref", "--no-deref", "HEAD", commit); err != nil {
		return fmt.Errorf("point bounded repository clone HEAD at %s: %w", ref.Name, err)
	}
	return nil
}

func fetchRemoteRepositoryRefs(ctx context.Context, runner CommandRunner, repoPath string, refs []remoteRepositoryRef, depth int) error {
	if len(refs) == 0 {
		return nil
	}
	if depth < 1 {
		depth = 1
	}
	args := []string{
		"--git-dir", repoPath,
		"fetch",
		"--quiet",
		"--no-tags",
	}
	args = appendBoundedFetchDepthArgs(args, depth)
	args = append(args, "origin")
	for _, ref := range refs {
		args = append(args, "+"+ref.Name+":"+ref.Name)
	}
	_, err := runner(ctx, "git", args...)
	if err != nil {
		return fmt.Errorf("fetch bounded repository refs: %w", err)
	}
	return nil
}

func appendBoundedFetchDepthArgs(args []string, depth int) []string {
	// ScanRepository excludes shallow boundary commits before running
	// patch-based secret detection, so bounded fetch roots do not produce
	// synthetic "added" lines against an empty tree.
	return append(args, "--depth", strconv.Itoa(depth))
}

func (s *Scanner) cloneCommandRunner(workdir string, cloneURL string) (CommandRunner, func(), error) {
	credential, useCredential, err := s.credentialForCloneURL(cloneURL)
	if err != nil {
		return nil, nil, err
	}
	if !useCredential {
		return s.run, func() {}, nil
	}
	if s.runEnv == nil {
		s.runEnv = defaultEnvCommandRunner
	}
	askpassPath, cleanup, err := writeGitAskPassScript(workdir)
	if err != nil {
		return nil, nil, err
	}

	env := []string{
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=" + askpassPath,
		"IDENTRAIL_GIT_USERNAME=" + credential.Username,
		"IDENTRAIL_GIT_PASSWORD=" + credential.Password,
	}
	return func(ctx context.Context, name string, args ...string) ([]byte, error) {
		output, runErr := s.runEnv(ctx, env, name, args...)
		if runErr != nil {
			if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
				return output, runErr
			}
			return output, sanitizeError(runErr, credential.Password)
		}
		return output, nil
	}, cleanup, nil
}

func parseRemoteRepositoryRefs(output []byte) ([]remoteRepositoryRef, string) {
	defaultRef := ""
	headSHA := ""
	refsByName := map[string]remoteRepositoryRef{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "ref: ") && strings.HasSuffix(line, "\tHEAD") {
			defaultRef = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "ref: "), "\tHEAD"))
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			continue
		}
		sha := strings.TrimSpace(parts[0])
		name := strings.TrimSpace(parts[1])
		if name == "HEAD" {
			headSHA = sha
			continue
		}
		if name == "" || strings.HasSuffix(name, "^{}") {
			continue
		}
		refsByName[name] = remoteRepositoryRef{Name: name, SHA: sha}
	}

	refs := make([]remoteRepositoryRef, 0, len(refsByName))
	for _, ref := range refsByName {
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool {
		return refs[i].Name < refs[j].Name
	})
	if defaultRef == "" && headSHA != "" {
		for _, ref := range refs {
			if strings.HasPrefix(ref.Name, "refs/heads/") && ref.SHA == headSHA {
				defaultRef = ref.Name
				break
			}
		}
	}
	if defaultRef == "" {
		for _, ref := range refs {
			if strings.HasPrefix(ref.Name, "refs/heads/") {
				defaultRef = ref.Name
				break
			}
		}
	}
	return refs, defaultRef
}

func buildRemoteRepositoryClonePlan(refs []remoteRepositoryRef, defaultRefName string, historyLimit int) (remoteRepositoryClonePlan, error) {
	if historyLimit < 1 {
		historyLimit = defaultHistoryLimit
	}
	if len(refs) == 0 {
		return remoteRepositoryClonePlan{}, fmt.Errorf("remote repository has no advertised refs")
	}

	defaultRef := refs[0]
	if defaultRefName != "" {
		for _, ref := range refs {
			if ref.Name == defaultRefName {
				defaultRef = ref
				break
			}
		}
	}

	extras := make([]remoteRepositoryRef, 0, len(refs)-1)
	for _, ref := range refs {
		if ref.Name == defaultRef.Name {
			continue
		}
		extras = append(extras, ref)
	}
	sort.SliceStable(extras, func(i, j int) bool {
		left := remoteRepositoryRefPriority(extras[i].Name)
		right := remoteRepositoryRefPriority(extras[j].Name)
		if left == right {
			return extras[i].Name < extras[j].Name
		}
		return left < right
	})

	const minFetchDepthForPatchScan = 2
	// Shallow boundary commits are excluded from patch scanning, so each
	// selected ref needs at least one parent available to keep its tip visible.
	extraDepth := minFetchDepthForPatchScan
	fetchDepthBudget := historyLimit
	if fetchDepthBudget < minFetchDepthForPatchScan {
		fetchDepthBudget = minFetchDepthForPatchScan
	}
	extraBudget := (fetchDepthBudget - minFetchDepthForPatchScan) / extraDepth
	if extraBudget < 0 {
		extraBudget = 0
	}
	if len(extras) > extraBudget {
		extras = extras[:extraBudget]
	}
	defaultDepth := fetchDepthBudget - (len(extras) * extraDepth)
	if defaultDepth < minFetchDepthForPatchScan {
		defaultDepth = minFetchDepthForPatchScan
	}
	return remoteRepositoryClonePlan{
		DefaultRef:   defaultRef,
		DefaultDepth: defaultDepth,
		ExtraRefs:    extras,
		ExtraDepth:   extraDepth,
	}, nil
}

func remoteRepositoryRefPriority(ref string) int {
	switch {
	case strings.HasPrefix(ref, "refs/tags/"):
		return 0
	case !strings.HasPrefix(ref, "refs/heads/"):
		return 1
	default:
		return 2
	}
}

func (s *Scanner) credentialForCloneURL(cloneURL string) (HTTPSCloneCredential, bool, error) {
	credential := s.cloneCredential
	if credential.Password == "" && credential.Username == "" && credential.Host == "" {
		return HTTPSCloneCredential{}, false, nil
	}
	if credential.Username == "" || credential.Password == "" || credential.Host == "" {
		return HTTPSCloneCredential{}, false, fmt.Errorf("incomplete HTTPS clone credential")
	}
	parsed, err := url.Parse(cloneURL)
	if err != nil || parsed == nil || parsed.Scheme == "" || parsed.Host == "" {
		return HTTPSCloneCredential{}, false, fmt.Errorf("authenticated clone target must be an absolute HTTPS URL")
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return HTTPSCloneCredential{}, false, fmt.Errorf("authenticated clone target must use HTTPS")
	}
	if !strings.EqualFold(parsed.Hostname(), credential.Host) {
		return HTTPSCloneCredential{}, false, fmt.Errorf("authenticated clone target host is not allowed")
	}
	return credential, true, nil
}

func writeGitAskPassScript(dir string) (string, func(), error) {
	file, err := os.CreateTemp(dir, "identrail-git-askpass-*")
	if err != nil {
		return "", nil, fmt.Errorf("create git askpass helper: %w", err)
	}
	path := file.Name()
	script := `#!/bin/sh
case "$1" in
  *Username*) printf '%s\n' "${IDENTRAIL_GIT_USERNAME:-x-access-token}" ;;
  *) printf '%s\n' "${IDENTRAIL_GIT_PASSWORD:-}" ;;
esac
`
	if _, err := file.WriteString(script); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", nil, fmt.Errorf("write git askpass helper: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", nil, fmt.Errorf("close git askpass helper: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		_ = os.Remove(path)
		return "", nil, fmt.Errorf("chmod git askpass helper: %w", err)
	}
	return path, func() { _ = os.Remove(path) }, nil
}

func (s *Scanner) shallowBoundaryExclusionArgs(ctx context.Context, repo repositoryLocation) ([]string, error) {
	output, err := s.git(ctx, repo, "rev-parse", "--git-path", "shallow")
	if err != nil {
		return nil, fmt.Errorf("resolve shallow boundary path: %w", err)
	}
	shallowPath := strings.TrimSpace(string(output))
	if shallowPath == "" {
		return nil, nil
	}
	if !filepath.IsAbs(shallowPath) {
		shallowPath = filepath.Join(repo.Path, shallowPath)
	}
	data, err := os.ReadFile(shallowPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read shallow boundary commits: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	args := make([]string, 0, len(lines))
	for _, line := range lines {
		sha := strings.TrimSpace(line)
		if sha == "" {
			continue
		}
		args = append(args, "^"+sha)
	}
	return args, nil
}

func (s *Scanner) listCommits(ctx context.Context, repo repositoryLocation, exclusionArgs []string) ([]string, error) {
	args := []string{"rev-list", "--all"}
	args = append(args, exclusionArgs...)
	args = append(args, "--max-count", strconv.Itoa(s.historyLimit))
	output, err := s.git(ctx, repo, args...)
	if err != nil {
		return nil, fmt.Errorf("list commits: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	commits := make([]string, 0, len(lines))
	for _, line := range lines {
		sha := strings.TrimSpace(line)
		if sha == "" {
			continue
		}
		commits = append(commits, sha)
	}
	return commits, nil
}

func (s *Scanner) listCommitsForOptions(ctx context.Context, repo repositoryLocation, options ScanOptions, exclusionArgs []string) ([]string, error) {
	switch options.Mode {
	case ScanModeDelta:
		args := []string{"rev-list", "--max-count", strconv.Itoa(s.historyLimit)}
		args = append(args, exclusionArgs...)
		if isZeroRevision(options.BaseRevision) || options.BaseRevision == "" {
			args = append(args, options.HeadRevision)
		} else {
			args = append(args, options.BaseRevision+".."+options.HeadRevision)
		}
		output, err := s.git(ctx, repo, args...)
		if err != nil {
			return nil, fmt.Errorf("list delta commits: %w", err)
		}
		return parseRevisionLines(output), nil
	case ScanModeQuick:
		if strings.TrimSpace(options.HeadRevision) == "" {
			return nil, nil
		}
		return []string{options.HeadRevision}, nil
	default:
		return s.listCommits(ctx, repo, exclusionArgs)
	}
}

func (s *Scanner) listHeadFiles(ctx context.Context, repo repositoryLocation) ([]string, error) {
	return s.listFilesAtRevision(ctx, repo, "HEAD")
}

func (s *Scanner) listFilesAtRevision(ctx context.Context, repo repositoryLocation, revision string) ([]string, error) {
	revision = strings.TrimSpace(revision)
	if revision == "" {
		revision = "HEAD"
	}
	output, err := s.git(ctx, repo, "ls-tree", "-r", "--name-only", revision)
	if err != nil {
		return nil, fmt.Errorf("list %s files: %w", revision, err)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	files := make([]string, 0, len(lines))
	for _, line := range lines {
		path := strings.TrimSpace(line)
		if path == "" {
			continue
		}
		files = append(files, path)
	}
	return files, nil
}

func (s *Scanner) loadSecretFindingPolicy(ctx context.Context, repo repositoryLocation, revision string) secretFindingPolicy {
	revision = strings.TrimSpace(revision)
	if revision == "" {
		revision = "HEAD"
	}
	output, err := s.git(ctx, repo, "show", revision+":.identrailignore")
	if err != nil {
		return secretFindingPolicy{}
	}
	return parseSecretFindingPolicy(output)
}

func (s *Scanner) resolveHeadCommit(ctx context.Context, repo repositoryLocation) (string, error) {
	return s.resolveRevision(ctx, repo, "HEAD")
}

func (s *Scanner) resolveRevision(ctx context.Context, repo repositoryLocation, revision string) (string, error) {
	revision = strings.TrimSpace(revision)
	if revision == "" {
		revision = "HEAD"
	}
	output, err := s.git(ctx, repo, "rev-parse", revision)
	if err != nil {
		return "", fmt.Errorf("resolve %s commit: %w", revision, err)
	}
	return strings.TrimSpace(string(output)), nil
}

func (s *Scanner) changedPathsForOptions(ctx context.Context, repo repositoryLocation, options ScanOptions) ([]string, error) {
	if len(options.ChangedPaths) > 0 {
		return normalizeScanChangedPaths(options.ChangedPaths), nil
	}
	if options.Mode != ScanModeDelta {
		return nil, nil
	}
	if strings.TrimSpace(options.HeadRevision) == "" {
		return nil, nil
	}
	if options.BaseRevision == "" || isZeroRevision(options.BaseRevision) {
		return nil, nil
	}
	output, err := s.git(ctx, repo, "diff", "--name-only", options.BaseRevision, options.HeadRevision)
	if err != nil {
		return nil, fmt.Errorf("list delta changed files: %w", err)
	}
	return normalizeScanChangedPaths(strings.Split(strings.TrimSpace(string(output)), "\n")), nil
}

func (s *Scanner) filesForHeadInspection(ctx context.Context, repo repositoryLocation, options ScanOptions) ([]string, error) {
	if options.Mode == ScanModeDelta && len(options.ChangedPaths) > 0 {
		headFiles, err := s.listFilesAtRevision(ctx, repo, options.HeadRevision)
		if err != nil {
			return nil, err
		}
		headSet := make(map[string]struct{}, len(headFiles))
		for _, file := range headFiles {
			headSet[file] = struct{}{}
		}
		existing := make([]string, 0, len(options.ChangedPaths))
		for _, path := range options.ChangedPaths {
			if _, ok := headSet[path]; ok {
				existing = append(existing, path)
			}
		}
		return existing, nil
	}
	return s.listFilesAtRevision(ctx, repo, options.HeadRevision)
}

func (s *Scanner) historyLogArgs(options ScanOptions, exclusionArgs []string) []string {
	args := []string{"log"}
	if options.Mode == ScanModeDelta {
		args = append(args, exclusionArgs...)
		if options.BaseRevision != "" && !isZeroRevision(options.BaseRevision) {
			args = append(args, options.BaseRevision+".."+options.HeadRevision)
		} else {
			args = append(args, options.HeadRevision)
		}
	} else {
		args = append(args, "--all")
		args = append(args, exclusionArgs...)
	}
	args = append(args, "--max-count", strconv.Itoa(s.historyLimit), "--no-color", "--unified=0", "--format=commit:%H", "-p")
	if options.Mode == ScanModeDelta && len(options.ChangedPaths) > 0 {
		args = append(args, "--")
		args = append(args, options.ChangedPaths...)
	}
	return args
}

func (s *Scanner) git(ctx context.Context, repo repositoryLocation, args ...string) ([]byte, error) {
	if repo.Bare {
		invocation := append([]string{"--git-dir", repo.Path}, args...)
		output, err := s.run(ctx, "git", invocation...)
		if err != nil {
			return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
		return output, nil
	}
	invocation := append([]string{"-C", repo.Path}, args...)
	output, err := s.run(ctx, "git", invocation...)
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return output, nil
}

// gitStream starts a git command and returns a streaming reader for its stdout.
// The caller must call the returned wait function to release process resources.
func (s *Scanner) gitStream(ctx context.Context, repo repositoryLocation, args ...string) (io.ReadCloser, func() error, error) {
	var invocation []string
	if repo.Bare {
		invocation = append([]string{"--git-dir", repo.Path}, args...)
	} else {
		invocation = append([]string{"-C", repo.Path}, args...)
	}
	cmd := newRepositoryCommand(ctx, "git", invocation...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	wait := func() error {
		_ = stdout.Close()
		if err := cmd.Wait(); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if msg := strings.TrimSpace(stderr.String()); msg != "" {
				return fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
			}
			return fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
		return nil
	}
	return stdout, wait, nil
}

// scanHistoryLines streams git log -p output from r, calling fn for each added line.
// fn should return true to continue processing or false to stop early.
// ctx cancellation is checked before each line and causes an early return.
func scanHistoryLines(ctx context.Context, r io.Reader, fn func(addedLine) bool) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	currentCommit := ""
	currentPath := ""
	currentLine := 0
	inHunk := false

	for sc.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "commit:"):
			currentCommit = strings.TrimSpace(strings.TrimPrefix(line, "commit:"))
			currentPath = ""
			currentLine = 0
			inHunk = false
		case strings.HasPrefix(line, "diff --git "):
			currentPath = parseDiffPath(line)
			currentLine = 0
			inHunk = false
		case strings.HasPrefix(line, "@@ "):
			match := hunkHeaderPattern.FindStringSubmatch(line)
			if len(match) != 2 {
				inHunk = false
				continue
			}
			parsed, err := strconv.Atoi(match[1])
			if err != nil || parsed < 1 {
				inHunk = false
				continue
			}
			currentLine = parsed
			inHunk = true
		default:
			if !inHunk {
				continue
			}
			if strings.HasPrefix(line, "+") {
				if strings.HasPrefix(line, "+++") {
					continue
				}
				if currentPath != "" && currentLine > 0 {
					if !fn(addedLine{
						Commit: currentCommit,
						Path:   currentPath,
						Line:   currentLine,
						Text:   strings.TrimSpace(strings.TrimPrefix(line, "+")),
					}) {
						return nil
					}
				}
				currentLine++
				continue
			}
			if strings.HasPrefix(line, " ") {
				currentLine++
				continue
			}
		}
	}
	return sc.Err()
}

type addedLine struct {
	Commit string
	Path   string
	Line   int
	Text   string
}

func normalizeScanOptions(options ScanOptions) ScanOptions {
	mode := strings.ToLower(strings.TrimSpace(options.Mode))
	switch mode {
	case ScanModeQuick, ScanModeDelta, ScanModeDeep:
	default:
		mode = ScanModeDeep
	}
	return ScanOptions{
		Mode:         mode,
		BaseRevision: strings.TrimSpace(options.BaseRevision),
		HeadRevision: strings.TrimSpace(options.HeadRevision),
		ChangedPaths: normalizeScanChangedPaths(options.ChangedPaths),
	}
}

func normalizeScanChangedPaths(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(paths))
	for _, path := range paths {
		item := strings.TrimSpace(strings.ReplaceAll(path, "\\", "/"))
		item = strings.TrimPrefix(item, "/")
		item = strings.TrimPrefix(item, "./")
		if item == "" || strings.Contains(item, "\x00") || strings.HasPrefix(item, "../") || strings.Contains(item, "/../") {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		normalized = append(normalized, item)
	}
	sort.Strings(normalized)
	return normalized
}

func parseRevisionLines(output []byte) []string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	commits := make([]string, 0, len(lines))
	for _, line := range lines {
		sha := strings.TrimSpace(line)
		if sha == "" {
			continue
		}
		commits = append(commits, sha)
	}
	return commits
}

func isZeroRevision(revision string) bool {
	trimmed := strings.TrimSpace(revision)
	return len(trimmed) >= 40 && strings.Trim(trimmed, "0") == ""
}

func firstNonEmptyScanString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func parseAddedLines(patch []byte) []addedLine {
	return parseHistoryAddedLines(patch)
}

func parseHistoryAddedLines(patch []byte) []addedLine {
	scanner := bufio.NewScanner(strings.NewReader(string(patch)))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	lines := []addedLine{}

	currentCommit := ""
	currentPath := ""
	currentLine := 0
	inHunk := false

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "commit:"):
			currentCommit = strings.TrimSpace(strings.TrimPrefix(line, "commit:"))
			currentPath = ""
			currentLine = 0
			inHunk = false
		case strings.HasPrefix(line, "diff --git "):
			currentPath = parseDiffPath(line)
			currentLine = 0
			inHunk = false
		case strings.HasPrefix(line, "@@ "):
			match := hunkHeaderPattern.FindStringSubmatch(line)
			if len(match) != 2 {
				inHunk = false
				continue
			}
			parsed, err := strconv.Atoi(match[1])
			if err != nil || parsed < 1 {
				inHunk = false
				continue
			}
			currentLine = parsed
			inHunk = true
		default:
			if !inHunk {
				continue
			}
			if strings.HasPrefix(line, "+") {
				if strings.HasPrefix(line, "+++") {
					continue
				}
				if currentPath != "" && currentLine > 0 {
					lines = append(lines, addedLine{
						Commit: currentCommit,
						Path:   currentPath,
						Line:   currentLine,
						Text:   strings.TrimSpace(strings.TrimPrefix(line, "+")),
					})
				}
				currentLine++
				continue
			}
			if strings.HasPrefix(line, " ") {
				currentLine++
				continue
			}
			if strings.HasPrefix(line, "-") || strings.HasPrefix(line, "\\") {
				continue
			}
		}
	}
	return lines
}

func parseDiffPath(line string) string {
	parts := strings.Fields(line)
	if len(parts) < 4 {
		return ""
	}
	path := strings.TrimSpace(parts[3])
	path = strings.Trim(path, "\"")
	return strings.TrimPrefix(path, "b/")
}

func looksLikeLocalPath(target string) bool {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return false
	}
	lower := strings.ToLower(trimmed)
	if strings.Contains(lower, "://") || strings.HasPrefix(lower, "git@") {
		return false
	}
	if strings.Count(trimmed, "/") == 1 &&
		!strings.HasPrefix(trimmed, "/") &&
		!strings.HasPrefix(trimmed, ".") &&
		!strings.HasPrefix(trimmed, "~") &&
		!strings.Contains(trimmed, "\\") {
		return false
	}
	return true
}

func localRepository(target string) (repositoryLocation, bool) {
	path := strings.TrimSpace(target)
	if path == "" {
		return repositoryLocation{}, false
	}
	if !looksLikeLocalPath(path) {
		return repositoryLocation{}, false
	}

	absolute, absErr := filepath.Abs(filepath.Clean(path))
	if absErr != nil {
		return repositoryLocation{}, false
	}

	if isGitWorktree(absolute) {
		return repositoryLocation{Path: absolute, Bare: false, Display: absolute}, true
	}
	if !isGitBareRepository(absolute) {
		return repositoryLocation{}, false
	}
	return repositoryLocation{Path: absolute, Bare: true, Display: absolute}, true
}

func isGitWorktree(path string) bool {
	output, err := exec.Command("git", "-C", path, "rev-parse", "--is-inside-work-tree").Output()
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(string(output)), "true")
}

func isGitBareRepository(path string) bool {
	output, err := exec.Command("git", "--git-dir", path, "rev-parse", "--is-bare-repository").Output()
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(string(output)), "true")
}

// IsLocalRepositoryTarget returns true when target resolves to a local worktree
// or bare git repository path on the scanner host filesystem.
func IsLocalRepositoryTarget(target string) bool {
	_, ok := localRepository(target)
	return ok
}

func normalizeRepositoryInput(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return trimmed
	}
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") || strings.HasPrefix(trimmed, "git@") || strings.HasPrefix(trimmed, "ssh://") {
		return trimmed
	}
	if strings.Count(trimmed, "/") == 1 && !strings.Contains(trimmed, " ") {
		return "https://github.com/" + strings.TrimSuffix(trimmed, ".git") + ".git"
	}
	return trimmed
}

func validateCloneURL(cloneURL string) error {
	trimmed := strings.TrimSpace(cloneURL)
	if trimmed == "" {
		return fmt.Errorf("repository target is required")
	}

	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "http://") {
		return fmt.Errorf("insecure repository url scheme http is not allowed; use https or ssh")
	}
	if !strings.Contains(lower, "://") {
		if host, ok := parseGitSCPTargetHost(trimmed); ok {
			return validateRepositoryHost(host)
		}
		return nil
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("parse repository target: %w", err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		if parsed.User != nil {
			return fmt.Errorf("repository target must not include credentials in URL userinfo")
		}
		return validateRepositoryHost(parsed.Hostname())
	case "ssh":
		if parsed.User != nil {
			if _, hasPassword := parsed.User.Password(); hasPassword {
				return fmt.Errorf("repository target must not include credentials in URL userinfo")
			}
			if strings.TrimSpace(parsed.User.Username()) == "" {
				return fmt.Errorf("repository target must not include credentials in URL userinfo")
			}
		}
		return validateRepositoryHost(parsed.Hostname())
	default:
		return fmt.Errorf("unsupported repository url scheme %q", parsed.Scheme)
	}
}

func parseGitSCPTargetHost(target string) (string, bool) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" || strings.ContainsAny(trimmed, " \t\r\n") {
		return "", false
	}

	bracketDepth := 0
	separator := -1
	for i, r := range trimmed {
		switch r {
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth == 0 {
				return "", false
			}
			bracketDepth--
		case ':':
			if bracketDepth == 0 {
				separator = i
				break
			}
		}
		if separator != -1 {
			break
		}
	}
	if bracketDepth != 0 || separator <= 0 || separator >= len(trimmed)-1 {
		return "", false
	}

	hostPart := strings.TrimSpace(trimmed[:separator])
	if at := strings.LastIndex(hostPart, "@"); at != -1 {
		hostPart = strings.TrimSpace(hostPart[at+1:])
	}
	if hostPart == "" {
		return "", false
	}
	if strings.HasPrefix(hostPart, "[") {
		if !strings.HasSuffix(hostPart, "]") || len(hostPart) <= 2 {
			return "", false
		}
		return hostPart[1 : len(hostPart)-1], true
	}
	if strings.ContainsAny(hostPart, "/[]") {
		return "", false
	}
	return hostPart, true
}

func validateRepositoryHost(host string) error {
	normalizedHost := strings.TrimSpace(host)
	if normalizedHost == "" {
		return fmt.Errorf("repository target host is required")
	}
	lowerHost := strings.TrimSuffix(strings.ToLower(normalizedHost), ".")
	if lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".localhost") {
		return fmt.Errorf("repository target host %q is not allowed", normalizedHost)
	}
	ipCandidate := lowerHost
	if zoneIndex := strings.Index(ipCandidate, "%"); zoneIndex != -1 {
		ipCandidate = ipCandidate[:zoneIndex]
	}
	ip := net.ParseIP(ipCandidate)
	if ip == nil {
		ip = parseLegacyIPv4Host(ipCandidate)
	}
	if ip != nil {
		if isBlockedRepositoryIP(ip) {
			return fmt.Errorf("repository target host %q is not allowed", normalizedHost)
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resolvedIPs, err := repositoryHostLookupIPs(ctx, lowerHost)
	if err != nil {
		return fmt.Errorf("repository target host %q could not be resolved: %w", normalizedHost, err)
	}
	for _, resolvedIP := range resolvedIPs {
		if isBlockedRepositoryIP(resolvedIP) {
			return fmt.Errorf("repository target host %q is not allowed", normalizedHost)
		}
	}
	return nil
}

func isBlockedRepositoryIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		repositorySharedAddressRange.Contains(ip)
}

func parseLegacyIPv4Host(host string) net.IP {
	parts := strings.Split(host, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nil
	}

	values := make([]uint64, len(parts))
	for i, part := range parts {
		if part == "" {
			return nil
		}
		value, err := strconv.ParseUint(part, 0, 32)
		if err != nil {
			return nil
		}
		values[i] = value
	}

	var combined uint64
	switch len(values) {
	case 1:
		if values[0] > 0xffffffff {
			return nil
		}
		combined = values[0]
	case 2:
		if values[0] > 0xff || values[1] > 0xffffff {
			return nil
		}
		combined = values[0]<<24 | values[1]
	case 3:
		if values[0] > 0xff || values[1] > 0xff || values[2] > 0xffff {
			return nil
		}
		combined = values[0]<<24 | values[1]<<16 | values[2]
	case 4:
		for _, value := range values {
			if value > 0xff {
				return nil
			}
		}
		combined = values[0]<<24 | values[1]<<16 | values[2]<<8 | values[3]
	}

	return net.IPv4(
		byte(combined>>24),
		byte(combined>>16),
		byte(combined>>8),
		byte(combined),
	).To4()
}

func mustParseCIDR(raw string) *net.IPNet {
	_, network, err := net.ParseCIDR(raw)
	if err != nil {
		panic(err)
	}
	return network
}

func redactMatch(line string, value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return line
	}
	return strings.ReplaceAll(line, trimmed, redactedToken(trimmed))
}

func redactedToken(value string) string {
	if len(value) <= 8 {
		return "[REDACTED]"
	}
	return fmt.Sprintf("[REDACTED:%s...%s]", value[:4], value[len(value)-4:])
}

func hashDeterministicID(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte("|"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hashSHA256(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func severityRank(severity domain.FindingSeverity) int {
	switch severity {
	case domain.SeverityCritical:
		return 0
	case domain.SeverityHigh:
		return 1
	case domain.SeverityMedium:
		return 2
	case domain.SeverityLow:
		return 3
	default:
		return 4
	}
}

func defaultCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := newRepositoryCommand(ctx, name, args...)
	return cmd.CombinedOutput()
}

func defaultEnvCommandRunner(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	cmd := newRepositoryCommand(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	return cmd.CombinedOutput()
}

func sanitizeError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	return errors.New(redactSecrets(err.Error(), secrets...))
}

func redactSecrets(text string, secrets ...string) string {
	redacted := text
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if secret == "" {
			continue
		}
		redacted = strings.ReplaceAll(redacted, secret, "[redacted]")
	}
	return redacted
}
