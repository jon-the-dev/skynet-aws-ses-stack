output "api_endpoint" {
  description = "API Gateway endpoint URL"
  value       = "${aws_apigatewayv2_api.api.api_endpoint}/send"
}

output "lambda_function_name" {
  description = "Lambda function name"
  value       = aws_lambda_function.send_email.function_name
}

output "lambda_function_arn" {
  description = "Lambda function ARN"
  value       = aws_lambda_function.send_email.arn
}

output "api_id" {
  description = "API Gateway ID"
  value       = aws_apigatewayv2_api.api.id
}

output "curl_test_command" {
  description = "Command to test the API"
  value       = <<-EOT
    curl -X POST ${aws_apigatewayv2_api.api.api_endpoint}/send \
      -H "Content-Type: application/json" \
      -d '{"subject": "Test from API", "message": "Hello from the contact form!", "from_name": "Test User", "from_email": "test@example.com"}'
  EOT
}
