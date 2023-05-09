package crownjewel

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	cfg "github.com/accuknox/auto-policy-discovery/src/config"
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

func GetMountPaths(client kubernetes.Interface, name, namespace string, labels LabelMap) ([]string, error) {
	CfgDB = cfg.GetCfgDB()
	// client := cluster.ConnectK8sClient()
	podList, err := client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod list: %v", err)
	}

	var policies []types.KubeArmorPolicy

	var mountPaths []string
	var matchedMountPaths []string
	var ms types.MatchSpec
	action := "Allow"
	// var sumResponses []*opb.Response

	for _, pod := range podList.Items {
		for _, container := range pod.Spec.Containers {
			// fmt.Println("\nContainer:", container.Name)
			for _, volumeMount := range container.VolumeMounts {
				fmt.Printf("\n---------------------------------------------\n")
				fmt.Printf("\n\n%s:%s\n", container.Name, volumeMount.MountPath)
				mountPaths = append(mountPaths, volumeMount.MountPath)

				sumResp, err := obs.GetSummaryData(&opb.Request{
					PodName:       pod.Name,
					NameSpace:     pod.Namespace,
					ContainerName: container.Name,
					Type:          "process,file",
				})
				if err != nil {
					log.Warn().Msgf("\n\nError getting summary data for pod %s, container %s, namespace %s: %s", pod.Name, container.Name, pod.Namespace, err.Error())
					continue
				}

				// fmt.Println("\n\n sumResp.FileData: ", sumResp.FileData)
				fmt.Println("\n\n volumeMount path: ", volumeMount.MountPath)

				for _, fileData := range sumResp.FileData {
					if strings.Contains(fileData.Destination, volumeMount.MountPath) {
						// found volume mount path matches summary file access
						fmt.Printf("\n\nFound volume mount %v in fileData %+v\n", volumeMount.MountPath, fileData.Destination)
						matchedMountPaths = append(matchedMountPaths, volumeMount.MountPath)
					}
				}
				fmt.Printf("\n*************************************************\n")

				policies = append(policies, createCrownjewelPolicy(ms, name, namespace, action, labels))
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
				fmt.Println("\n\n MOUNT PATHS: \n", mountPaths)
				fmt.Println("\n\n MATCHED PATHS: \n", matchedMountPaths)

			}
		}
	}

	return mountPaths, nil
}

// func getSensitiveAssetsPolicies(pols []types.KnoxSystemPolicy) []types.KnoxSystemPolicy {
// 	// var crownjewelPolicies []types.KnoxSystemPolicy

// 	client := cluster.ConnectK8sClient()
// 	mpts, _ := GetMountPaths(client)
// 	fmt.Println("mpts: ", mpts)
// 	policy := buildSystemPolicy()
// 	policy.Metadata["type"] = "file"
// 	policy.Spec.File = types.KnoxSys{}

// }

// - logs (group basis on pod and label) ->  Generate WPFS db -> Generate KnoxSystempolicy

// WPFS -> fields -> Name|Clustername|Ns|containername|label|Type|fromsource|fileset(list of dest- dir/filepath)

func buildSystemPolicy(name, ns, action string) types.KubeArmorPolicy {
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
				MatchLabels: map[string]string{
					"app.kubernetes.io/name": ns,
					"component":              "server",
				}},
			Action:  "Allow",
			Message: "Sensitive assets and process control policy",
			File: types.KnoxSys{
				// MatchPaths: []types.KnoxMatchPaths{
				// 	{
				// 		Path:       "/hello",
				// 		FromSource: nil,
				// 	},
				// },
				MatchDirectories: []types.KnoxMatchDirectories{
					{
						Dir:        "/directory/",
						Recursive:  true,
						FromSource: nil,
						Action:     "Allow",
					},
				},
			},
		},
	}
}

func createCrownjewelPolicy(ms types.MatchSpec, name, namespace, action string, labels LabelMap) types.KubeArmorPolicy {
	// policy := types.KnoxSystemPolicy{
	// 	APIVersion: "v1",
	// 	Kind:       "CrownjewelSystemPolicy",
	// 	Metadata:   map[string]string{},
	// 	Spec: types.KnoxSystemSpec{
	// 		Severity: 1, // by default
	// 		Selector: types.Selector{
	// 			MatchLabels: labels},
	// 		Action: "Allow",
	// 	},
	// }
	policy := buildSystemPolicy(name, namespace, action)
	// policy.Metadata["type"] = "file" // SYS_OP_FILE
	// policy.Spec.File = types.KnoxSys{}

	return policy
}
