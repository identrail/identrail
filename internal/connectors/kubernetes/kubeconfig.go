package kubernetes

import (
	"errors"
	"strings"

	"github.com/goccy/go-yaml"
)

var ErrInvalidKubeconfig = errors.New("invalid kubeconfig")

type KubeconfigSummary struct {
	CurrentContext string
	Cluster        string
	Server         string
}

type kubeconfigDocument struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server string `yaml:"server"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Users []struct {
		Name string `yaml:"name"`
	} `yaml:"users"`
}

// ValidateKubeconfig performs structural validation without logging or
// returning credentials. Live namespace listing belongs to the runtime driver.
func ValidateKubeconfig(payload string, preferredContext string) (KubeconfigSummary, error) {
	if strings.TrimSpace(payload) == "" {
		return KubeconfigSummary{}, ErrInvalidKubeconfig
	}
	var doc kubeconfigDocument
	if err := yaml.Unmarshal([]byte(payload), &doc); err != nil {
		return KubeconfigSummary{}, ErrInvalidKubeconfig
	}
	if len(doc.Clusters) == 0 || len(doc.Contexts) == 0 || len(doc.Users) == 0 {
		return KubeconfigSummary{}, ErrInvalidKubeconfig
	}
	contextName := strings.TrimSpace(preferredContext)
	if contextName == "" {
		contextName = strings.TrimSpace(doc.CurrentContext)
	}
	if contextName == "" {
		return KubeconfigSummary{}, ErrInvalidKubeconfig
	}
	clusterName := ""
	for _, context := range doc.Contexts {
		if strings.TrimSpace(context.Name) == contextName {
			clusterName = strings.TrimSpace(context.Context.Cluster)
			break
		}
	}
	if clusterName == "" {
		return KubeconfigSummary{}, ErrInvalidKubeconfig
	}
	server := ""
	for _, cluster := range doc.Clusters {
		if strings.TrimSpace(cluster.Name) == clusterName {
			server = strings.TrimSpace(cluster.Cluster.Server)
			break
		}
	}
	if server == "" {
		return KubeconfigSummary{}, ErrInvalidKubeconfig
	}
	return KubeconfigSummary{
		CurrentContext: contextName,
		Cluster:        clusterName,
		Server:         server,
	}, nil
}
