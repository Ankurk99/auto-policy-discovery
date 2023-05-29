package crownjewel

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	"github.com/accuknox/auto-policy-discovery/src/libs"
	obs "github.com/accuknox/auto-policy-discovery/src/observability"
	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
	"github.com/accuknox/auto-policy-discovery/src/systempolicy"
	"github.com/accuknox/auto-policy-discovery/src/types"
	"github.com/rs/zerolog/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

// var log *zerolog.Logger

// CfgDB is the global variable representing the configuration of the database
var CfgDB types.ConfigDB

type LabelMap = map[string]string

func getProcessList(client kubernetes.Interface, namespace string, labels types.LabelMap) ([]string, error) {
	var processList []string
	duplicatePaths := make(map[string]bool)

	podList, err := client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		LabelSelector: libs.LabelMapToString(labels),
	})
	if err != nil {
		log.Warn().Msg(err.Error())
	}
	for _, pod := range podList.Items {
		for _, container := range pod.Spec.Containers {
			sumResp, err := obs.GetSummaryData(&opb.Request{
				PodName:       pod.Name,
				NameSpace:     pod.Namespace,
				ContainerName: container.Name,
				Type:          "process,file",
			})
			if err != nil {
				// log.Warn().Msgf("Error getting summary data for pod %s, container %s, namespace %s: %s", pod.Name, container.Name, pod.Namespace, err.Error())
				break
			}

			for _, fileData := range sumResp.FileData {
				if !duplicatePaths[fileData.Source] {
					processList = append(processList, fileData.Source)
					duplicatePaths[fileData.Source] = true
				}
			}
		}
	}
	return processList, nil
}

func usedMountPath(client kubernetes.Interface, namespace string, labels types.LabelMap) ([]string, map[string]string, error) {
	var sumResponses []string
	fromSource := make(map[string]string)

	podList, err := client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		LabelSelector: libs.LabelMapToString(labels),
	})
	if err != nil {
		log.Warn().Msg(err.Error())
	}

	for _, pod := range podList.Items {
		for _, container := range pod.Spec.Containers {
			sumResp, err := obs.GetSummaryData(&opb.Request{
				PodName:       pod.Name,
				NameSpace:     pod.Namespace,
				ContainerName: container.Name,
				Type:          "process,file",
			})
			if err != nil {
				// log.Warn().Msgf("Error getting summary data for pod %s, container %s, namespace %s: %s", pod.Name, container.Name, pod.Namespace, err.Error())
				break
			}

			for _, fileData := range sumResp.FileData {
				sumResponses = append(sumResponses, fileData.Destination)
				fromSource[fileData.Destination] = fileData.Source
			}
		}
	}
	return sumResponses, fromSource, nil
}

func getVolumeMountPaths(client kubernetes.Interface, labels LabelMap) ([]string, error) {
	podList, err := client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		LabelSelector: libs.LabelMapToString(labels),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod list: %v", err)
	}

	var mountPaths []string

	for _, pod := range podList.Items {
		for _, container := range pod.Spec.Containers {
			for _, volumeMount := range container.VolumeMounts {
				// fmt.Printf("\n\n%s:%s\n", container.Name, volumeMount.MountPath)
				mountPaths = append(mountPaths, volumeMount.MountPath)
			}
		}
	}
	return mountPaths, nil
}

func accessedMountPaths(sumResp, mnt []string) ([]string, error) {
	var matchedMountPaths []string
	duplicatePaths := make(map[string]bool)

	for _, sumRespPath := range sumResp {
		for _, mntPath := range mnt {
			if strings.Contains(sumRespPath, mntPath) && !duplicatePaths[mntPath] {
				matchedMountPaths = append(matchedMountPaths, mntPath)
				duplicatePaths[mntPath] = true
			}
		}
	}
	return matchedMountPaths, nil
}

func GetMountPaths(client kubernetes.Interface, name, namespace string, labels LabelMap) ([]string, error) {
	CfgDB = cfg.GetCfgDB()

	var policies []types.KnoxSystemPolicy

	var mountPaths []string
	var matchedMountPaths []string
	var ms types.MatchSpec
	action := "Allow"

	// mount paths being used (from observability)
	sumResp, fromSrc, _ := usedMountPath(client, namespace, labels)

	// total mount paths being used (from k8s cluster)
	mnt, _ := getVolumeMountPaths(client, labels)

	// mount paths being used and are present in observability data (accessed mount paths)
	matchedMountPaths, _ = accessedMountPaths(sumResp, mnt)

	// process paths being used and are present in observability data
	matchedProcessPaths, _ := getProcessList(client, namespace, labels)

	policies = append(policies, createCrownjewelPolicy(ms, name, namespace, action, labels, mnt, matchedMountPaths, matchedProcessPaths, fromSrc))

	jsonData, err := json.Marshal(policies)
	if err != nil {
		fmt.Println("Error marshaling", err)
		return nil, nil
	}
	yamlData, err := yaml.JSONToYAML(jsonData)
	if err != nil {
		fmt.Println("Error converting JSON to YAML:", err)
		return nil, nil
	}
	fmt.Println(string(yamlData))

	systempolicy.UpdateSysPolicies(policies)

	return mountPaths, nil
}

// func GetSensitiveAssetsPolicies(name, ns, action string, labels LabelMap) []types.KnoxSystemPolicy {
// 	// var crownjewelPolicies []types.KnoxSystemPolicy

// 	var result []types.KnoxSystemPolicy
// 	client := cluster.ConnectK8sClient()
// 	mpts, err := getVolumeMountPaths(client, labels)
// 	if err != nil {
// 		fmt.Printf("Error getting volume mount paths")
// 	}

// 	for _, path := range mpts {
// 		fmt.Println("Path:", path)
// 	}

// 	return result
// }

func buildSystemPolicy(name, ns, action string, labels LabelMap, matchDirs []types.KnoxMatchDirectories, matchPaths []types.KnoxMatchPaths) types.KnoxSystemPolicy {
	return types.KnoxSystemPolicy{
		APIVersion: "v1",
		Kind:       "KubeArmorPolicy",
		Metadata: map[string]string{
			"name":      "autopol-assets-" + name,
			"namespace": ns,
		},
		Spec: types.KnoxSystemSpec{
			Severity: 7,
			Selector: types.Selector{
				MatchLabels: labels},
			Action:  "Allow", // global action - default Allow
			Message: "Sensitive assets and process control policy",
			File: types.KnoxSys{
				MatchDirectories: matchDirs,
			},
			Process: types.KnoxSys{
				MatchPaths: matchPaths,
			},
		},
	}
}

func createCrownjewelPolicy(ms types.MatchSpec, name, namespace, action string, labels LabelMap, matchedDirPts, matchedMountPts, matchedProcessPts []string, fromSrc map[string]string) types.KnoxSystemPolicy {
	var matchDirs []types.KnoxMatchDirectories
	for _, dirpath := range matchedDirPts {
		action = "Block"
		for _, mountPt := range matchedMountPts {
			if dirpath == mountPt {
				action = "Allow"
				break
			}
		}

		var fromSourceVal []types.KnoxFromSource
		for key, value := range fromSrc {
			if strings.Contains(key, dirpath) {
				// Check if the value already exists in fromSourceVal
				exists := false
				for _, existing := range fromSourceVal {
					if existing.Path == value {
						exists = true
						break
					}
				}
				if !exists {
					fromSourceVal = append(fromSourceVal, types.KnoxFromSource{Path: value})
				}
			}
		}

		matchDir := types.KnoxMatchDirectories{
			Dir:        dirpath + "/",
			Recursive:  true,
			FromSource: fromSourceVal,
			Action:     action,
		}

		if action == "Allow" {
			// Block that dir from global access
			matchAllowedDir := types.KnoxMatchDirectories{
				Dir:       dirpath + "/",
				Recursive: true,
				Action:    "Block",
			}
			matchDirs = append(matchDirs, matchAllowedDir)
		}

		matchDirs = append(matchDirs, matchDir)
	}

	// default allow access to root directory "/"
	matchDir := types.KnoxMatchDirectories{
		Dir:       "/",
		Recursive: true,
	}

	matchDirs = append(matchDirs, matchDir)

	var matchPaths []types.KnoxMatchPaths
	for _, processpath := range matchedProcessPts {
		matchPath := types.KnoxMatchPaths{
			Path:   processpath,
			Action: "Allow",
		}
		matchPaths = append(matchPaths, matchPath)
	}
	policy := buildSystemPolicy(name, namespace, action, labels, matchDirs, matchPaths)
	return policy
}
