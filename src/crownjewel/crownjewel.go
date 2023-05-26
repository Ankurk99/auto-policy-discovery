package crownjewel

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/accuknox/auto-policy-discovery/src/cluster"
	cfg "github.com/accuknox/auto-policy-discovery/src/config"
	"github.com/accuknox/auto-policy-discovery/src/libs"
	obs "github.com/accuknox/auto-policy-discovery/src/observability"
	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
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
				continue
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
				fmt.Printf("\n---------------------------------------------\n")
				fmt.Printf("\n\n%s:%s\n", container.Name, volumeMount.MountPath)
				mountPaths = append(mountPaths, volumeMount.MountPath)
				fmt.Printf("\n---------------------------------------------\n")
			}
		}
	}
	fmt.Println("\n--------- MountPaths ------------\n", mountPaths)
	return mountPaths, nil
}

func accessedMountPaths(sumResp, mnt []string) ([]string, error) {
	var matchedMountPaths []string
	for _, sumRespPath := range sumResp {
		for _, mntPath := range mnt {
			if strings.Contains(sumRespPath, mntPath) {
				matchedMountPaths = append(matchedMountPaths, mntPath)
			}
		}
	}
	return matchedMountPaths, nil
}

func GetMountPaths(client kubernetes.Interface, name, namespace string, labels LabelMap) ([]string, error) {
	CfgDB = cfg.GetCfgDB()
	// client := cluster.ConnectK8sClient()
	// podList, err := client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to get pod list: %v", err)
	// }

	var policies []types.KubeArmorPolicy

	var mountPaths []string
	var matchedMountPaths []string
	var ms types.MatchSpec
	action := "Allow"

	sumResp, _ := usedMountPath(client, namespace, labels)
	mnt, _ := getVolumeMountPaths(client, labels)

	matchedMountPaths, _ = accessedMountPaths(sumResp, mnt)

	fmt.Println("\n\n sumResp: \n", sumResp)
	fmt.Println("\n\n mnt: \n", mnt)

	fmt.Println("\n\n MATCHED PATHS: \n", matchedMountPaths)

	fmt.Printf("\n*************************************************\n")

	for _, matchedMountPts := range matchedMountPaths {
		policies = append(policies, createCrownjewelPolicy(ms, name, namespace, action, labels, matchedMountPts))
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
	fmt.Println("YAML ^")

	// fmt.Println("\n*************************************************\n", policies)

	return mountPaths, nil
}

func GetSensitiveAssetsPolicies(name, ns, action string, labels LabelMap) []types.KubeArmorPolicy {
	// var crownjewelPolicies []types.KnoxSystemPolicy

	var result []types.KubeArmorPolicy
	client := cluster.ConnectK8sClient()
	mpts, err := getVolumeMountPaths(client, labels)
	if err != nil {
		fmt.Printf("Error getting volume mount paths")
	}

	for _, path := range mpts {
		fmt.Println("Path:", path)
	}

	return result
}

// - logs (group basis on pod and label) ->  Generate WPFS db -> Generate KnoxSystempolicy

// WPFS -> fields -> Name|Clustername|Ns|containername|label|Type|fromsource|fileset(list of dest- dir/filepath)

func buildSystemPolicy(name, ns, action string, labels LabelMap, matchDirs types.KnoxMatchDirectories) types.KubeArmorPolicy {
	return types.KubeArmorPolicy{
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
				// MatchPaths: []types.KnoxMatchPaths{
				// 	{
				// 		Path:       "/hello",
				// 		FromSource: nil,
				// 	},
				// },
				MatchDirectories: []types.KnoxMatchDirectories{matchDirs},
			},
		},
	}
}

func createCrownjewelPolicy(ms types.MatchSpec, name, namespace, action string, labels LabelMap, matchedMountPts string) types.KubeArmorPolicy {
	matchDirs := types.KnoxMatchDirectories{
		Dir:        matchedMountPts,
		Recursive:  true,
		FromSource: nil,
		Action:     action,
	}
	policy := buildSystemPolicy(name, namespace, action, labels, matchDirs)
	return policy
}
