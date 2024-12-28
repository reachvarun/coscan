package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"encoding/json"
	"regexp"

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

	"golang.org/x/time/rate"
)

// FetchLiveAMIPatchStatus retrieves a list of AMI patch statuses for Amazon-owned images.
func FetchLiveAMIPatchStatus(sess *session.Session, filterPattern string) map[string]string {
    ec2Svc := ec2.New(sess)
    input := &ec2.DescribeImagesInput{
        Owners: []*string{aws.String("amazon")}, // Filter for Amazon-owned AMIs
        Filters: []*ec2.Filter{
            {Name: aws.String("name"), Values: []*string{aws.String(filterPattern)}},
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
func ScanForPatches(sess *session.Session, instances []*ec2.Instance, filterCritical bool, filterPattern string) {
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
		    CheckAMIPatchStatus(instance, sess, filterPattern)
		    continue
		}

		if len(result.Patches) == 0 {
		    log.Printf("No patches found for instance: %s. Checking AMI as fallback.", instanceID)
		    CheckAMIPatchStatus(instance, sess, filterPattern) // Invoke fallback for empty results
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
func CheckAMIPatchStatus(instance *ec2.Instance, sess *session.Session, filterPattern string) {
    liveAMIs := FetchLiveAMIPatchStatus(sess, filterPattern)
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

	// Get AMI filter pattern from query parameters or use default
	amiFilter := "amzn2-ami-hvm-*"
	if customFilter := r.URL.Query().Get("amiFilter"); customFilter != "" {
	    if isValidFilterPattern(customFilter) {
        	amiFilter = customFilter
	    } else {
       		log.Printf("Invalid filter pattern: %s", customFilter)
	        http.Error(w, "Invalid filter pattern", http.StatusBadRequest)
	        return
	    }
	}

	type ProviderResult struct {
		Provider string      `json:"provider"`
		Success  bool        `json:"success"`
		Message  string      `json:"message"`
		Data     interface{} `json:"data,omitempty"`
	}

	results := []ProviderResult{}

	type loginResult struct {
		provider string
		err      error
		session  *session.Session
	}

	loginResults := make(chan loginResult, 1)

	// Start authentication attempts concurrently
	var awsSession *session.Session
	go func() {
		sess, err := AWSLogin()
		loginResults <- loginResult{"AWS", err, sess}
	}()
	// Uncomment for Azure and GCP
	//go func() { results <- loginResult{"Azure", AzureLogin(), nil} }()
	//go func() { results <- loginResult{"GCP", GCPLogin(), nil} }()

	errors := []string{}
	totalResults := 1 // Only AWS is active for now

	for i := 0; i < totalResults; i++ {
	    result := <-loginResults
	    if result.err != nil {
		log.Printf("Failed to authenticate with %s: %v", result.provider, result.err)
	        errors = append(errors, fmt.Sprintf("%s: %v", result.provider, result.err))
		results = append(results, ProviderResult{result.provider, false, result.err.Error(), nil})
	    } else {
	        log.Printf("Successfully authenticated with %s", result.provider)
		results = append(results, ProviderResult{result.provider, true, "Authenticated successfully", nil})
	        if result.provider == "AWS" {
	            awsSession = result.session
	        }
	    }
	}

	if len(errors) > 0 {
		log.Printf("Authentication errors: %v", errors)
	}

	// List VMs for authenticated providers
	if awsSession != nil {
		log.Println("Listing AWS VMs...")
		instances, err := ListAWSVMs(awsSession)
		if err != nil {
			log.Printf("Failed to list AWS VMs: %v", err)
			results = append(results, ProviderResult{"AWS-ListVMs", false, err.Error(), nil})
		} else {
			log.Println("AWS VMs listed successfully.")
			vmData := []string{}
			for _, instance := range instances {
				vmData = append(vmData, aws.StringValue(instance.InstanceId))
			}
			results = append(results, ProviderResult{"AWS-ListVMs", true, "Listed VMs successfully", vmData})

			if scanPatches {
				log.Println("Scanning AWS instances for patches...")
				ScanForPatches(awsSession, instances, filterCritical, amiFilter)
				results = append(results, ProviderResult{"AWS-ScanPatches", true, "Patch scanning completed", nil})
			}
		}
	}

	log.Println("Listing Azure VMs...")
	ListAzureVMs()
	results = append(results, ProviderResult{"Azure", false, "Functionality not implemented", nil})

	log.Println("Listing GCP VMs...")
	ListGCPVMs()
	results = append(results, ProviderResult{"GCP", false, "Functionality not implemented", nil})

	// Respond with the results as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
	fmt.Fprintln(w, "Successfully authenticated and listed VMs for available cloud providers. Check logs for details.")
}

// Retrieve CodeQL scanning results for a repository via Github REST API
func ScanLambdasHandler(w http.ResponseWriter, r *http.Request) {
    limiter := rate.NewLimiter(5, 50) // 5 requests per second, burst of 50

    // Wait for rate limiter permission
    if err := limiter.Wait(context.Background()); err != nil {
        http.Error(w, "Rate limit exceeded, please try again later.", http.StatusTooManyRequests)
        return
    }

    // Read environment variables
    githubToken := os.Getenv("GITHUB_PAT")
    githubUsername := os.Getenv("GITHUB_USER")
    repo := r.URL.Query().Get("repo") // Repository name from query parameters

    if !isValidRepo(repo) {
        http.Error(w, "Invalid repository name", http.StatusBadRequest)
        return
    }


    if githubToken == "" || repo == "" {
        http.Error(w, "Missing required environment variables or query parameters", http.StatusBadRequest)
        return
    }

    // Construct API request
    apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/code-scanning/alerts", githubUsername, repo)
    req, err := http.NewRequest("GET", apiURL, nil)
    if err != nil {
        http.Error(w, "Failed to create API request: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Add Authorization header
    req.Header.Set("Authorization", "Bearer "+githubToken)
    req.Header.Set("Accept", "application/vnd.github+json")

    // Make the API request
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        http.Error(w, "Failed to contact GitHub API: "+err.Error(), http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    // Check for errors in the response
    if resp.StatusCode != http.StatusOK {
        http.Error(w, "GitHub API responded with: "+resp.Status, resp.StatusCode)
        return
    }

    // Parse the response body
    var alerts []map[string]interface{}
    err = json.NewDecoder(resp.Body).Decode(&alerts)
    if err != nil {
        http.Error(w, "Failed to parse GitHub API response: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Check if there are no alerts
    if len(alerts) == 0 {
        w.Header().Set("Content-Type", "text/plain")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("[OK]\n"))
        return
    }

    // Respond with the parsed alerts
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(alerts)
}

// isValidRepo validates the repository name against GitHub naming conventions.
func isValidRepo(repo string) bool {
    // GitHub repository name regex: 1-100 alphanumeric, hyphens, underscores
    validRepoRegex := `^[a-zA-Z0-9\-_]{1,100}$`
    matched, err := regexp.MatchString(validRepoRegex, repo)
    if err != nil {
        log.Printf("Error validating repo name: %v", err)
        return false
    }
    return matched
}

// isValidFilterPattern validates the filter pattern against expected formats.
func isValidFilterPattern(pattern string) bool {
    // Allow alphanumeric characters, hyphens, asterisks, and slashes
    validPatternRegex := `^[a-zA-Z0-9\-/\*]+$`
    matched, err := regexp.MatchString(validPatternRegex, pattern)
    if err != nil {
        log.Printf("Error validating filter pattern: %v", err)
        return false
    }
    return matched
}

func main() {
	http.HandleFunc("/scanvm", ScanVMHandler)
	http.HandleFunc("/scanlambdas", ScanLambdasHandler)
	port := ":8080"
	log.Printf("Starting server on port %s...", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
