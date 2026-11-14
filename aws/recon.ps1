# READ-ONLY reconnaissance of the AWS sandbox. Creates, changes and deletes nothing.
# Run:  powershell -ExecutionPolicy Bypass -File aws\recon.ps1
# Output masks 12-digit account IDs. Paste the summary into aws/RECON.md by hand.
$env:AWS_REGION = if ($env:AWS_REGION) { $env:AWS_REGION } else { "us-east-1" }

function Check([string]$name, [string[]]$cmd) {
    $out = & aws @cmd 2>&1 | Out-String
    $out = $out -replace '\d{12}', '<account-id>'
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[CONFIRMED] $name" -ForegroundColor Green
        Write-Host ($out.Trim() -split "`n" | Select-Object -First 15 | Out-String)
    } elseif ($out -match 'AccessDenied|not authorized|UnauthorizedOperation|AccessDeniedException') {
        Write-Host "[PERMISSION DENIED] $name" -ForegroundColor Yellow
    } else {
        Write-Host "[ERROR / NOT FOUND] $name : $($out.Trim() -split "`n" | Select-Object -First 2)" -ForegroundColor Red
    }
}

Check "Caller identity (role)"        @("sts","get-caller-identity","--query","Arn","--output","text")
Check "Region"                        @("configure","get","region")
Check "Rekognition collections"       @("rekognition","list-collections")
Check "Lambda functions (names only)" @("lambda","list-functions","--query","Functions[].FunctionName","--output","text")
Check "API Gateway HTTP APIs"         @("apigatewayv2","get-apis","--query","Items[].Name","--output","text")
Check "API Gateway REST APIs"         @("apigateway","get-rest-apis","--query","items[].name","--output","text")
Check "DynamoDB tables"               @("dynamodb","list-tables")
Check "Bedrock Anthropic models"      @("bedrock","list-foundation-models","--by-provider","anthropic","--query","modelSummaries[].modelId","--output","text")
Check "Bedrock Amazon models"         @("bedrock","list-foundation-models","--by-provider","amazon","--query","modelSummaries[].modelId","--output","text")
Check "Bedrock inference profiles"    @("bedrock","list-inference-profiles","--query","inferenceProfileSummaries[].inferenceProfileId","--output","text")
Check "CloudWatch log groups"         @("logs","describe-log-groups","--max-items","5","--query","logGroups[].logGroupName","--output","text")
Check "CloudFormation (needed by SAM)" @("cloudformation","list-stacks","--max-items","5","--query","StackSummaries[].StackName","--output","text")
Check "Cognito identity pools"        @("cognito-identity","list-identity-pools","--max-results","5")
Check "IAM roles (can we read IAM?)"  @("iam","list-roles","--max-items","5","--query","Roles[].RoleName","--output","text")
Check "Our role's attached policies"  @("iam","list-attached-role-policies","--role-name","WSParticipantRole")

Write-Host ""
Write-Host "Not testable read-only: Face Liveness session creation, Lambda/IAM role creation, Bedrock invoke."
Write-Host "Check those in the console, or with explicit team approval."
