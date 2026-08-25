//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type policyDocument struct {
	Statement []struct {
		Action any `json:"Action"`
	} `json:"Statement"`
}

func main() {
	raw, err := os.ReadFile("identrail-readonly-policy.json")
	if err != nil {
		fatal(err)
	}
	var policy policyDocument
	if err := json.Unmarshal(raw, &policy); err != nil {
		fatal(err)
	}
	actions := map[string]struct{}{}
	for _, statement := range policy.Statement {
		switch typed := statement.Action.(type) {
		case string:
			actions[strings.ToLower(typed)] = struct{}{}
		case []any:
			for _, item := range typed {
				action, ok := item.(string)
				if !ok {
					fatal(fmt.Errorf("policy action must be string"))
				}
				actions[strings.ToLower(action)] = struct{}{}
			}
		default:
			fatal(fmt.Errorf("policy action must be string or array"))
		}
	}

	required := []string{
		"apprunner:describeservice",
		"apprunner:listservices",
		"batch:describecomputeenvironments",
		"batch:describejobdefinitions",
		"bedrock-agentcore:getagentruntime",
		"bedrock-agentcore:getbrowser",
		"bedrock-agentcore:getcodeinterpreter",
		"bedrock-agentcore:getgateway",
		"bedrock-agentcore:getgatewaytarget",
		"bedrock-agentcore:getmemory",
		"bedrock-agentcore:listagentruntimeendpoints",
		"bedrock-agentcore:listagentruntimes",
		"bedrock-agentcore:listbrowsers",
		"bedrock-agentcore:listcodeinterpreters",
		"bedrock-agentcore:listgateways",
		"bedrock-agentcore:listgatewaytargets",
		"bedrock-agentcore:listmemories",
		"cloudformation:liststackinstances",
		"codebuild:batchgetprojects",
		"codebuild:listprojects",
		"codepipeline:getpipeline",
		"codepipeline:getpipelinestate",
		"codepipeline:listpipelines",
		"dynamodb:describetable",
		"dynamodb:getresourcepolicy",
		"dynamodb:listtables",
		"dynamodb:listtagsofresource",
		"ec2:describeiaminstanceprofileassociations",
		"ec2:describeinstances",
		"ec2:describelaunchtemplates",
		"ec2:describelaunchtemplateversions",
		"ec2:describeregions",
		"ecr:describeimages",
		"ecr:describerepositories",
		"ecr:getlifecyclepolicy",
		"ecr:getregistryscanningconfiguration",
		"ecr:getrepositorypolicy",
		"ecr:listtagsforresource",
		"ecs:describeservices",
		"ecs:describetaskdefinition",
		"ecs:listclusters",
		"ecs:listservices",
		"ecs:listtaskdefinitions",
		"eks:describecluster",
		"eks:describefargateprofile",
		"eks:describenodegroup",
		"eks:describepodidentityassociation",
		"eks:listclusters",
		"eks:listfargateprofiles",
		"eks:listnodegroups",
		"eks:listpodidentityassociations",
		"elasticmapreduce:describecluster",
		"elasticmapreduce:listclusters",
		"events:listeventbuses",
		"events:listrules",
		"events:listtagsforresource",
		"events:listtargetsbyrule",
		"glue:getcrawlers",
		"glue:getjobs",
		"iam:getpolicy",
		"iam:getpolicyversion",
		"iam:getaccountsummary",
		"iam:getinstanceprofile",
		"iam:getrole",
		"iam:getrolepolicy",
		"iam:listaccountaliases",
		"iam:listattachedrolepolicies",
		"iam:listrolepolicies",
		"iam:listroles",
		"iam:simulateprincipalpolicy",
		"lambda:listaliases",
		"lambda:listeventsourcemappings",
		"lambda:listfunctions",
		"lambda:listtags",
		"lambda:listversionsbyfunction",
		"kms:describekey",
		"kms:getkeypolicy",
		"kms:getkeyrotationstatus",
		"kms:listaliases",
		"kms:listgrants",
		"kms:listkeys",
		"kms:listresourcetags",
		"pipes:describepipe",
		"pipes:listpipes",
		"rds:describedbclusters",
		"rds:describedbinstances",
		"rds:describedbproxies",
		"rds:listtagsforresource",
		"s3:getbucketacl",
		"s3:getbucketlocation",
		"s3:getbucketownershipcontrols",
		"s3:getbucketpolicy",
		"s3:getbucketpublicaccessblock",
		"s3:getbuckettagging",
		"s3:getencryptionconfiguration",
		"s3:listaccesspoints",
		"s3:listallmybuckets",
		"sagemaker:describedomain",
		"sagemaker:describeendpoint",
		"sagemaker:describeendpointconfig",
		"sagemaker:describemodel",
		"sagemaker:describenotebookinstance",
		"sagemaker:describepipeline",
		"sagemaker:describeprocessingjob",
		"sagemaker:describetrainingjob",
		"sagemaker:describetransformjob",
		"sagemaker:listdomains",
		"sagemaker:listendpoints",
		"sagemaker:listmodels",
		"sagemaker:listnotebookinstances",
		"sagemaker:listpipelines",
		"sagemaker:listprocessingjobs",
		"sagemaker:listtrainingjobs",
		"sagemaker:listtransformjobs",
		"scheduler:getschedule",
		"scheduler:listschedules",
		"secretsmanager:describesecret",
		"secretsmanager:getresourcepolicy",
		"secretsmanager:listsecrets",
		"secretsmanager:listsecretversionids",
		"sns:getsubscriptionattributes",
		"sns:gettopicattributes",
		"sns:listsubscriptionsbytopic",
		"sns:listtagsforresource",
		"sns:listtopics",
		"sqs:getqueueattributes",
		"sqs:listqueues",
		"sqs:listqueuetags",
		"ssm:describeparameters",
		"ssm:listtagsforresource",
		"states:describestatemachine",
		"states:liststatemachines",
		"states:listtagsforresource",
		"sts:getcalleridentity",
		"organizations:describeorganization",
		"organizations:listaccountsforparent",
		"organizations:listdelegatedadministrators",
		"organizations:listdelegatedservicesforaccount",
		"organizations:listorganizationalunitsforparent",
		"organizations:listroots",
	}
	missing := make([]string, 0)
	for _, action := range required {
		if _, ok := actions[action]; !ok {
			missing = append(missing, action)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		fatal(fmt.Errorf("missing required connector actions: %s", strings.Join(missing, ", ")))
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
