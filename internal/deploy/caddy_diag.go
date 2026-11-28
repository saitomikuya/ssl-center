package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	pathpkg "path"
	"sort"
	"strings"

	"ssl-center/internal/model"
)

type dockerMountInfo struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	Mode        string `json:"Mode"`
	RW          bool   `json:"RW"`
}

type dockerInspectState struct {
	Status     string `json:"Status"`
	Running    bool   `json:"Running"`
	Restarting bool   `json:"Restarting"`
}

type dockerInspectConfig struct {
	Image string `json:"Image"`
}

type dockerInspectPayload struct {
	State  dockerInspectState  `json:"State"`
	Config dockerInspectConfig `json:"Config"`
	Mounts []dockerMountInfo   `json:"Mounts"`
}

// DiscoverCaddy inspects Docker containers and Caddy bind mounts on host without mutating DB state.
func (t *Transport) DiscoverCaddy(ctx context.Context, host *model.Host, targetContainer string) (*model.DiscoverCaddyResponse, error) {
	if host == nil {
		return nil, fmt.Errorf("host must not be nil")
	}
	probe := *host
	if trimmed := strings.TrimSpace(targetContainer); trimmed != "" {
		probe.CaddyContainer = trimmed
	}

	resp := &model.DiscoverCaddyResponse{
		DetectedContainers: make([]model.DetectedContainer, 0),
	}

	err := t.WithSession(ctx, &probe, func(sCtx context.Context) error {
		runner := func(cmd string) (*model.ExecResult, error) {
			return t.Exec(sCtx, &probe, cmd)
		}
		existsFn := func(filePath string) *bool {
			if _, readErr := t.ReadFile(sCtx, &probe, filePath); readErr == nil {
				v := true
				return &v
			}
			v := false
			return &v
		}

		testRes := &model.HostTestResult{}
		t.diagnoseCaddy(&probe, testRes, isLocalHost(&probe), runner, existsFn)

		resp.DockerOK = testRes.DockerOK
		resp.CaddyIssueCode = testRes.CaddyIssueCode
		resp.CaddyfileExists = testRes.CaddyfileExists
		resp.DetectedCaddyConfig = testRes.DetectedCaddyConfig
		resp.Message = t.redact(testRes.Message)
		if len(testRes.DetectedContainers) > 0 {
			resp.DetectedContainers = testRes.DetectedContainers
		} else if testRes.DockerOK {
			resp.DetectedContainers = listDockerContainers(runner)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (t *Transport) diagnoseCaddy(
	host *model.Host,
	res *model.HostTestResult,
	isLocal bool,
	runner func(string) (*model.ExecResult, error),
	existsFn func(string) *bool,
) (string, bool) {
	prefix := "SSH OK"
	invalidPrefix := "SSH connection succeeded"
	if isLocal {
		prefix = "Local host OK"
		invalidPrefix = "Local host OK"
	}

	container := strings.TrimSpace(host.CaddyContainer)
	if container == "" {
		container = "caddy"
	}
	if err := model.ValidateContainerName(container); err != nil {
		res.CaddyIssueCode = "invalid_container_name"
		res.Message = fmt.Sprintf("%s; invalid Caddy container name: %v", invalidPrefix, err)
		return model.CaddyStatusUnknown, false
	}

	infoRes, infoErr := runner("docker info --format '{{.ServerVersion}}'")
	if !isDockerDaemonAvailable(infoRes, infoErr) {
		detail := ""
		if infoErr != nil {
			detail = infoErr.Error()
		} else if infoRes != nil {
			detail = strings.TrimSpace(firstNonEmpty(infoRes.Stderr, infoRes.Stdout))
		}
		if detail == "" {
			detail = "empty server version from docker info"
		}
		lowerDetail := strings.ToLower(detail)
		if strings.Contains(lowerDetail, "permission denied") || strings.Contains(lowerDetail, "docker.sock") {
			res.CaddyIssueCode = "docker_sock_permission"
		} else {
			res.CaddyIssueCode = "docker_unavailable"
		}
		res.Message = fmt.Sprintf("%s; Docker unavailable: %s", prefix, detail)
		return model.CaddyStatusUnknown, false
	}

	res.DockerOK = true
	inspectCmd := fmt.Sprintf("docker inspect --format '{{json .}}' %s", model.ShellQuote(container))
	inspectRes, inspectErr := runner(inspectCmd)
	if inspectErr == nil && inspectRes != nil && inspectRes.ExitCode == 0 {
		obj, parseOK := parseDockerInspectResult(inspectRes.Stdout)
		if !parseOK {
			res.CaddyIssueCode = "container_not_found"
			res.Message = fmt.Sprintf("%s; Docker OK; Caddy container %q inspect failed: unexpected inspect output", prefix, container)
			return model.CaddyStatusUnknown, false
		}

		if len(obj.Mounts) > 0 {
			res.DetectedCaddyConfig = inferCaddyConfigFromMounts(container, obj.Mounts, host)
		}

		hostCaddyfile := strings.TrimSpace(host.CaddyHostCaddyfile)
		if hostCaddyfile != "" && existsFn != nil {
			res.CaddyfileExists = existsFn(hostCaddyfile)
		}

		restarting := obj.State.Restarting || strings.EqualFold(obj.State.Status, "restarting")
		if obj.State.Running && !restarting {
			res.CaddyRunning = true
			verCmd := fmt.Sprintf("docker exec %s caddy version", model.ShellQuote(container))
			if verRes, verErr := runner(verCmd); verErr == nil && verRes != nil && verRes.ExitCode == 0 {
				res.CaddyVersion = strings.TrimSpace(verRes.Stdout)
			}
			res.Message = fmt.Sprintf("%s; Docker OK; Caddy container running", prefix)
			return model.CaddyStatusRunning, true
		}

		if restarting {
			res.CaddyIssueCode = "container_restarting"
			res.Message = fmt.Sprintf("%s; Docker OK; Caddy container %q is restarting", prefix, container)
			return model.CaddyStatusStopped, false
		}

		res.CaddyIssueCode = "container_stopped"
		res.Message = fmt.Sprintf("%s; Docker OK; Caddy container %q is stopped", prefix, container)
		return model.CaddyStatusStopped, false
	}

	detail := ""
	if inspectErr != nil {
		detail = inspectErr.Error()
	} else if inspectRes != nil {
		detail = strings.TrimSpace(firstNonEmpty(inspectRes.Stderr, inspectRes.Stdout))
	}
	res.CaddyIssueCode = "container_not_found"
	res.Message = fmt.Sprintf("%s; Docker OK; Caddy container %q inspect failed: %s", prefix, container, detail)

	// Container not found: probe all containers so user can pick and auto-fill.
	containers := listDockerContainers(runner)
	if len(containers) > 0 {
		res.DetectedContainers = containers
		if candidate := pickBestCaddyCandidate(containers); candidate != nil {
			candInspectCmd := fmt.Sprintf("docker inspect --format '{{json .}}' %s", model.ShellQuote(candidate.Name))
			if candRes, candErr := runner(candInspectCmd); candErr == nil && candRes != nil && candRes.ExitCode == 0 {
				if obj, ok := parseDockerInspectResult(candRes.Stdout); ok {
					res.DetectedCaddyConfig = inferCaddyConfigFromMounts(candidate.Name, obj.Mounts, host)
				}
			}
		}
	}
	return model.CaddyStatusUnknown, false
}

func parseDockerInspectResult(raw string) (*dockerInspectPayload, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, false
	}
	if strings.HasPrefix(trimmed, "[") {
		var arr []dockerInspectPayload
		if err := json.Unmarshal([]byte(trimmed), &arr); err == nil && len(arr) > 0 {
			return &arr[0], true
		}
	}
	if strings.HasPrefix(trimmed, "{") {
		var obj dockerInspectPayload
		if err := json.Unmarshal([]byte(trimmed), &obj); err == nil {
			return &obj, true
		}
	}
	if strings.EqualFold(trimmed, "true") {
		return &dockerInspectPayload{
			State: dockerInspectState{Running: true, Status: "running"},
		}, true
	}
	if strings.EqualFold(trimmed, "false") {
		return &dockerInspectPayload{
			State: dockerInspectState{Running: false, Status: "exited"},
		}, true
	}
	return nil, false
}

func listDockerContainers(runner func(string) (*model.ExecResult, error)) []model.DetectedContainer {
	psRes, psErr := runner("docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}'")
	if psErr != nil || psRes == nil || psRes.ExitCode != 0 {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(psRes.Stdout), "\n")
	out := make([]model.DetectedContainer, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		if name == "" {
			continue
		}
		image := strings.TrimSpace(parts[1])
		state := ""
		status := ""
		if len(parts) >= 3 {
			state = strings.TrimSpace(parts[2])
		}
		if len(parts) >= 4 {
			status = strings.TrimSpace(parts[3])
		}
		running := strings.EqualFold(state, "running")
		isCaddy := strings.Contains(strings.ToLower(name), "caddy") || strings.Contains(strings.ToLower(image), "caddy")
		out = append(out, model.DetectedContainer{
			Name:    name,
			Image:   image,
			State:   state,
			Status:  status,
			Running: running,
			IsCaddy: isCaddy,
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].IsCaddy != out[j].IsCaddy {
			return out[i].IsCaddy
		}
		if out[i].Running != out[j].Running {
			return out[i].Running
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func pickBestCaddyCandidate(containers []model.DetectedContainer) *model.DetectedContainer {
	for i := range containers {
		if containers[i].IsCaddy && containers[i].Running {
			return &containers[i]
		}
	}
	for i := range containers {
		if containers[i].IsCaddy {
			return &containers[i]
		}
	}
	return nil
}

func inferCaddyConfigFromMounts(containerName string, mounts []dockerMountInfo, host *model.Host) *model.DetectedCaddyConfig {
	cfg := &model.DetectedCaddyConfig{
		ContainerName:      containerName,
		ContainerCaddyfile: "/etc/caddy/Caddyfile",
		ContainerCertDir:   "/certs",
	}
	if host != nil {
		if strings.TrimSpace(host.CaddyContainerCaddyfile) != "" {
			cfg.ContainerCaddyfile = strings.TrimSpace(host.CaddyContainerCaddyfile)
		}
		if strings.TrimSpace(host.CaddyContainerCertDir) != "" {
			cfg.ContainerCertDir = strings.TrimSpace(host.CaddyContainerCertDir)
		}
	}

	targetCF := pathpkg.Clean(cfg.ContainerCaddyfile)
	bestCFScore := -1
	for _, mt := range mounts {
		if mt.Type != "bind" || strings.TrimSpace(mt.Source) == "" || strings.TrimSpace(mt.Destination) == "" {
			continue
		}
		dest := pathpkg.Clean(strings.TrimSpace(mt.Destination))
		src := pathpkg.Clean(strings.TrimSpace(mt.Source))

		if dest == targetCF {
			if len(dest) > bestCFScore {
				bestCFScore = len(dest)
				cfg.HostCaddyfile = src
				cfg.MountType = "file"
			}
		} else if dest == "/etc/caddy" || (dest != "/" && strings.HasPrefix(targetCF, dest+"/")) {
			if len(dest) > bestCFScore {
				bestCFScore = len(dest)
				rel := strings.TrimPrefix(targetCF, dest)
				cfg.HostCaddyfile = pathpkg.Join(src, rel)
				cfg.MountType = "dir"
			}
		}

		// Detect cert directory mount
		if dest == pathpkg.Clean(cfg.ContainerCertDir) || dest == "/certs" || strings.Contains(strings.ToLower(dest), "cert") {
			if cfg.HostCertDir == "" {
				cfg.HostCertDir = src
				cfg.ContainerCertDir = dest
			}
		}
	}

	return cfg
}
