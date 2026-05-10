package repoexposure

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// Option customizes scanner behavior.
type Option func(*Scanner)

// Scanner detects secret exposure and misconfiguration findings in Git repositories.
type Scanner struct {
	run          CommandRunner
	now          func() time.Time
	historyLimit int
	maxFindings  int
}

// ScanResult summarizes one repository exposure scan.
type ScanResult struct {
	Repository     string           `json:"repository"`
	CommitsScanned int              `json:"commits_scanned"`
	FilesScanned   int              `json:"files_scanned"`
	Findings       []domain.Finding `json:"findings"`
	Truncated      bool             `json:"truncated"`
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

// ScanRepository performs read-only scanning for commit-history secret exposure and HEAD misconfigurations.
func (s *Scanner) ScanRepository(ctx context.Context, target string) (ScanResult, error) {
	repo := strings.TrimSpace(target)
	if repo == "" {
		return ScanResult{}, fmt.Errorf("repository target is required")
	}

	started := s.now().UTC()
	location, cleanup, err := s.prepareRepository(ctx, repo)
	if err != nil {
		return ScanResult{}, err
	}
	defer cleanup()

	commits, err := s.listCommits(ctx, location)
	if err != nil {
		return ScanResult{}, err
	}

	findings := make([]domain.Finding, 0, s.maxFindings)
	seen := map[string]struct{}{}
	truncated := false

	logArgs := []string{"log", "--all", "--max-count", strconv.Itoa(s.historyLimit), "--no-color", "--unified=0", "--format=commit:%H", "-p"}
	historyReader, waitLog, logErr := s.gitStream(ctx, location, logArgs...)
	if logErr != nil {
		return ScanResult{}, fmt.Errorf("scan commit history: %w", logErr)
	}
	scanErr := scanHistoryLines(ctx, historyReader, func(added addedLine) bool {
		secretFindings := detectSecretFindings(location.Display, added.Commit, added.Path, added.Line, added.Text, started)
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

	filesScanned := 0
	if !truncated {
		headFiles, fileErr := s.listHeadFiles(ctx, location)
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
			content, readErr := s.git(ctx, location, "show", "HEAD:"+filePath)
			if readErr != nil {
				return ScanResult{}, fmt.Errorf("read HEAD file %s: %w", filePath, readErr)
			}
			if len(content) == 0 || len(content) > maxFileSizeBytes || !utf8.Valid(content) {
				continue
			}
			filesScanned++
			for _, finding := range detectMisconfigFindings(location.Display, filePath, content, started) {
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
		StartedAt:      started,
		CompletedAt:    s.now().UTC(),
	}, nil
}

type repositoryLocation struct {
	Path    string
	Bare    bool
	Display string
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
	mirrorPath := filepath.Join(workdir, "repo.git")
	if _, runErr := s.run(ctx, "git", "clone", "--mirror", "--quiet", cloneURL, mirrorPath); runErr != nil {
		cleanup()
		return repositoryLocation{}, nil, fmt.Errorf("clone repository: %w", runErr)
	}
	return repositoryLocation{Path: mirrorPath, Bare: true, Display: target}, cleanup, nil
}

func (s *Scanner) listCommits(ctx context.Context, repo repositoryLocation) ([]string, error) {
	args := []string{"rev-list", "--all", "--max-count", strconv.Itoa(s.historyLimit)}
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

func (s *Scanner) listHeadFiles(ctx context.Context, repo repositoryLocation) ([]string, error) {
	output, err := s.git(ctx, repo, "ls-tree", "-r", "--name-only", "HEAD")
	if err != nil {
		return nil, fmt.Errorf("list HEAD files: %w", err)
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
	cmd := exec.CommandContext(ctx, "git", invocation...)
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
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}
