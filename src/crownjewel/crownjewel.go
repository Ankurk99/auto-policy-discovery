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

// type containerMountPath struct {
// 	podName       string
// 	podNamespace  string
// 	containerName string
// 	mountPath     string
// }

//	func mountPathUsed(containersSATokenMountPath []containerMountPath, sumResponses []*opb.Response) bool {
//		for _, containerMountPath := range containersSATokenMountPath {
//			for _, sumResp := range sumResponses {
//				for _, fileData := range sumResp.FileData {
//					if sumResp.ContainerName == containerMountPath.containerName {
//						if containerMountPath.mountPath == fileData.Destination {
//							return true
//						}
//					}
//				}
//			}
//		}
//		return false
//	}
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

func usedMountPath(client kubernetes.Interface, namespace string, labels types.LabelMap) ([]string, error) {
	var sumResponses []string
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
			}
		}
	}
	fmt.Println("\n--------- Sumresponses------------\n", sumResponses)
	return sumResponses, nil
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
				// fmt.Printf("\n---------------------------------------------\n")
				fmt.Printf("\n\n%s:%s\n", container.Name, volumeMount.MountPath)
				mountPaths = append(mountPaths, volumeMount.MountPath)
				// fmt.Printf("\n---------------------------------------------\n")
			}
		}
	}
	fmt.Println("\n--------- Labels ------------", labels)
	fmt.Println("\n--------- MountPaths ------------", mountPaths)
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
	sumResp, _ := usedMountPath(client, namespace, labels)

	// total mount paths being used (from k8s cluster)
	mnt, _ := getVolumeMountPaths(client, labels)

	// mount paths being used and are present in observability data (accessed mount paths)
	matchedMountPaths, _ = accessedMountPaths(sumResp, mnt)

	// process paths being used and are present in observability data
	matchedProcessPaths, _ := getProcessList(client, namespace, labels)

	if matchedMountPaths == nil {
		action = "Block"
	}

	fmt.Println("\n\n sumResp: \n", sumResp)

	fmt.Println("\n\n MATCHED PATHS: \n", matchedMountPaths)

	// fmt.Printf("\n*************************************************\n")

	for _, matchedMountPts := range mnt {
		for _, matchedProcess := range matchedProcessPaths {
			policies = append(policies, createCrownjewelPolicy(ms, name, namespace, action, labels, matchedMountPts, matchedProcess))
		}
	}

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

func buildSystemPolicy(name, ns, action string, labels LabelMap, matchDirs types.KnoxMatchDirectories, matchPaths types.KnoxMatchPaths) types.KnoxSystemPolicy {
	return types.KnoxSystemPolicy{
		APIVersion: "security.kubearmor.com/v1",
		Kind:       "KubeArmorPolicy",
		Metadata: map[string]string{
			"name":      "autopol-assets-" + name,
			"namespace": ns,
		},
		Spec: types.KnoxSystemSpec{
			Severity: 7,
			Selector: types.Selector{
				MatchLabels: labels},
			Action:  "Allow",
			Message: "Sensitive assets and process control policy",
			File: types.KnoxSys{
				MatchDirectories: []types.KnoxMatchDirectories{matchDirs},
			},
			Process: types.KnoxSys{
				MatchPaths: []types.KnoxMatchPaths{matchPaths},
			},
		},
	}
}

func createCrownjewelPolicy(ms types.MatchSpec, name, namespace, action string, labels LabelMap, matchedMountPts string, matchedProcessPts string) types.KnoxSystemPolicy {
	matchDirs := types.KnoxMatchDirectories{
		Dir:        matchedMountPts,
		Recursive:  true,
		FromSource: nil,
		Action:     action,
	}

	// var matchPaths []types.KnoxMatchPaths

	// for _, processPath := range matchedProcessPts {
	// 	matchPath := types.KnoxMatchPaths{
	// 		Path: processPath,
	// 	}
	// 	matchPaths = append(matchPaths, matchPath)
	// }

	matchPaths := types.KnoxMatchPaths{
		Path:   matchedProcessPts,
		Action: "Allow",
	}
	policy := buildSystemPolicy(name, namespace, action, labels, matchDirs, matchPaths)
	return policy
}
