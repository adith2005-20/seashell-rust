use reqwest::Client;
use serde_json::json;
use serde::{Deserialize, Serialize};

pub async fn chat(client: &Client, query: &str) -> Result<String, Box<dyn std::error::Error>> {
    let api_key = "AIzaSyCjxSZlW4QZDHZ5UDCZT4kULhmK1xT9F7w"; // Replace with your actual API key
    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={}",
        api_key
    );
    
    // Updated prompt with more emphasis on not using quotes with echo -e
    let prompt = r#"You are helping debug failed Linux commands in a custom shell called SeaShell.

When a command fails, provide ONLY the corrected command with no explanation, no code blocks, and no backticks.

IMPORTANT RULES:
1. Feel free to use && operations
2. Never use semicolons (;) for operations that need to preserve state
3. For file creation, use echo -e WITHOUT ANY QUOTES AROUND THE CONTENT:
   CORRECT: echo -e for i in range(10):\n    print(i * 2) > file.py
   WRONG: echo -e "for i in range(10):\n    print(i * 2)" > file.py
4. Remove ALL quotation marks from echo commands - they are NOT needed and cause problems
5. If asked to create a script or code file, generate the content with proper newlines

Examples of GOOD responses:
- ls -la
- echo -e for i in range(10):\n    print(i * 2) > even_numbers.py
- find . -name *.txt

Examples of BAD responses (don't do these):
- ```bash\nls -la\n```
- mkdir test; cd test
- echo "print('hello')" > hello.py
- ANY response with quotes around the echo content
- VERY IMPORTANT: ANY response with escape sequences like this: printf(\"\n\"); It is simply not required. The expected correct way is printf("\n"); .

If asked to make a file that performs a task (like 'make a python file that prints even numbers'), create the content WITHOUT quotes in the echo command.

The query is: "#;

    let request_body = json!({
        "contents": [{
            "parts": [{
                "text": format!("{}{}", prompt, query)
            }]
        }]
    });

    let response = client.post(&url)
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await?;
        
    let response_text = response.text().await?;
    // Parse the response into JSON for easier inspection.
    let response_json: serde_json::Value = serde_json::from_str(&response_text)?;
    
    // Expecting the shell command at: candidates[0].content.parts[0].text
    if let Some(command) = response_json.get("candidates")
        .and_then(|v| v.get(0))
        .and_then(|v| v.get("content"))
        .and_then(|v| v.get("parts"))
        .and_then(|v| v.get(0))
        .and_then(|v| v.get("text"))
        .and_then(|v| v.as_str())
    {
        Ok(command.to_string())
    } else {
        // If the response structure is not as expected, include the raw JSON in the error.
        Err(format!("Invalid API response: {}", response_json).into())
    }
}
