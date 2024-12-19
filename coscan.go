package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/sts"
	"google.golang.org/api/option"
	"google.golang.org/api/compute/v1"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

func FetchLiveAMIPatchStatus(sess *session.Session) map[string]string {
    ec2Svc := ec2.New(sess)
    input := &ec2.DescribeImagesInput{
        Owners: []*string{aws.String("amazon")}, // Filter for Amazon-owned AMIs
        Filters: []*ec2.Filter{
            {Name: aws.String("name"), Values: []*string{aws.String("amzn2-ami-hvm-*")}},
        },
    }

    result, err := ec2Svc.DescribeImages(input)
    if err != nil {
        log.Fatalf("Failed to fetch live AMI patch status: %v", err)
    }

    liveAMIs := make(map[string]string)
    for _, image := range result.Images {
        liveAMIs[*image.ImageId] = fmt.Sprintf("%s - %s", aws.StringValue(image.Name), aws.StringValue(image.Description))
    }
    return liveAMIs
}

// AWSLogin handles AWS authentication and returns a session
func AWSLogin() (*session.Session, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(os.Getenv("AWS_REGION")),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %w", err)
	}

	stsClient := sts.New(sess)
	_, err = stsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate AWS credentials: %w", err)
	}

	return sess, nil
}

// ListAWSVMs lists all EC2 instances in AWS
func ListAWSVMs(sess *session.Session) ([]*ec2.Instance, error) {
	svc := ec2.New(sess)
	input := &ec2.DescribeInstancesInput{}

	result, err := svc.DescribeInstances(input)
	if err != nil {
		return nil, fmt.Errorf("failed to list AWS EC2 instances: %w", err)
	}

	instances := []*ec2.Instance{}
	log.Println("AWS EC2 Instances:")
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			log.Printf("Instance ID: %s, State: %s", aws.StringValue(instance.InstanceId), aws.StringValue(instance.State.Name))
			instances = append(instances, instance)
		}
	}
	return instances, nil
}

// ScanForPatches scans instances for all patches or critical patches
func ScanForPatches(sess *session.Session, instances []*ec2.Instance, filterCritical bool) {
	ssmSvc := ssm.New(sess)
	log.Println("Scanning for patches using AWS SSM...")

	patchStateFilter := "All"
	if filterCritical {
		patchStateFilter = "Missing"
	}

	for _, instance := range instances {
		instanceID := aws.StringValue(instance.InstanceId)
		if aws.StringValue(instance.State.Name) != "running" {
			continue // Skip non-running instances
		}

		log.Printf("Scanning instance: %s", instanceID)

		patchInput := &ssm.DescribeInstancePatchesInput{
			InstanceId: aws.String(instanceID),
			Filters: []*ssm.PatchOrchestratorFilter{
				{
					Key:    aws.String("State"),
					Values: []*string{aws.String(patchStateFilter)},
				},
			},
		}

		result, err := ssmSvc.DescribeInstancePatches(patchInput)

		if err != nil {
		    log.Printf("SSM unavailable for instance %s, falling back to AMI comparison.", instanceID)
		    CheckAMIPatchStatus(instance, sess)
		    continue
		}

		if len(result.Patches) == 0 {
		    log.Printf("No patches found for instance: %s. Checking AMI as fallback.", instanceID)
		    CheckAMIPatchStatus(instance, sess) // Invoke fallback for empty results
		    continue
		}

		log.Printf("Instance %s has the following patches:", instanceID)
		for _, patch := range result.Patches {
			log.Printf("  - KB: %s, State: %s", aws.StringValue(patch.Title), aws.StringValue(patch.State))
			if patch.CVEIds != nil {
				log.Printf("    CVE: %s", aws.StringValue(patch.CVEIds))
			}
		}
	}

	log.Println("Patch scan completed.")
}

// CheckAMIPatchStatus checks AMI ID against known unpatched images
func CheckAMIPatchStatus(instance *ec2.Instance, sess *session.Session) {
    liveAMIs := FetchLiveAMIPatchStatus(sess)
    imageID := aws.StringValue(instance.ImageId)
    instanceID := aws.StringValue(instance.InstanceId)

    if status, exists := liveAMIs[imageID]; exists {
        log.Printf("Instance %s uses AMI: %s", instanceID, status)
    } else {
        log.Printf("Instance %s uses AMI: %s - Not found in live AMI list. Review manually.", instanceID, imageID)
    }
}

// AzureLogin handles Azure authentication
func AzureLogin() error {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure credential: %w", err)
	}

	_, err = cred.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	if err != nil {
		return fmt.Errorf("failed to authenticate Azure credentials: %w", err)
	}

	return nil
}

// ListAzureVMs lists VMs in Azure (placeholder implementation)
func ListAzureVMs() {
	log.Println("ListAzureVMs: This functionality is a placeholder for Azure VM listing")
}

// GCPLogin handles GCP authentication
func GCPLogin() error {
	ctx := context.Background()
	credentialsFile := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if credentialsFile == "" {
		return fmt.Errorf("GOOGLE_APPLICATION_CREDENTIALS environment variable not set")
	}

	_, err := compute.NewService(ctx, option.WithCredentialsFile(credentialsFile))
	if err != nil {
		return fmt.Errorf("failed to authenticate GCP credentials: %w", err)
	}

	return nil
}

// ListGCPVMs lists VMs in GCP (placeholder implementation)
func ListGCPVMs() {
	log.Println("ListGCPVMs: This functionality is a placeholder for GCP VM listing")
}

// ScanVMHandler handles the HTTP request to log in to cloud providers and list VMs
func ScanVMHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	scanPatches := strings.ToLower(query.Get("scanPatches")) == "true"
	filterCritical := strings.ToLower(query.Get("filter")) == "critical"

	type loginResult struct {
		provider string
		err      error
		session  *session.Session
	}

	results := make(chan loginResult, 1)

	// Start authentication attempts concurrently
	var awsSession *session.Session
	go func() {
		sess, err := AWSLogin()
		results <- loginResult{"AWS", err, sess}
	}()
	//go func() { results <- loginResult{"Azure", AzureLogin(), nil} }()
	//go func() { results <- loginResult{"GCP", GCPLogin(), nil} }()

	errors := []string{}
	totalResults := 1 // Only AWS is active for now

	for i := 0; i < totalResults; i++ {
	    result := <-results
	    if result.err != nil {
	        errors = append(errors, fmt.Sprintf("%s: %v", result.provider, result.err))
	    } else {
	        log.Printf("Successfully authenticated with %s", result.provider)
	        if result.provider == "AWS" {
	            awsSession = result.session
	        }
	    }
	}

	if len(errors) > 0 {
		http.Error(w, "Failed to authenticate with: "+fmt.Sprintf("%v", errors), http.StatusInternalServerError)
		return
	}

	// List VMs for authenticated providers
	if awsSession != nil {
		log.Println("Listing AWS VMs...")
		instances, err := ListAWSVMs(awsSession)
		if err != nil {
			http.Error(w, "Failed to list AWS VMs: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if scanPatches {
			ScanForPatches(awsSession, instances, filterCritical)
		}
	}

	log.Println("Listing Azure VMs...")
	ListAzureVMs()

	log.Println("Listing GCP VMs...")
	ListGCPVMs()

	fmt.Fprintln(w, "Successfully authenticated and listed VMs for available cloud providers. Check logs for details.")
}

func main() {
	http.HandleFunc("/scanvm", ScanVMHandler)
	port := ":8080"
	log.Printf("Starting server on port %s...", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
