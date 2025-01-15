# Function to display header information (Splash Screen & Title)
Clear-Host  # Clears the terminal screen

# ASCII Art splash screen
$asciiArtUrl = "https://raw.githubusercontent.com/Annabxlla/art/refs/heads/master/art.ps1"
$asciiArtScript = Invoke-RestMethod -Uri $asciiArtUrl
Invoke-Expression $asciiArtScript  # Print the ASCII Art in the terminal
# Encode and decode title text
$encodedTitle = "VXBkYXRlZCBieSBAYW5uYWJ4bGxhIG9uIERpc2NvcmQg4pml" # Joke about base64 being "encrypted"
$titleText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedTitle))

# Set terminal window title
$Host.UI.RawUI.WindowTitle = $titleText
