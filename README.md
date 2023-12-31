# Rodo - An auto API Record and Replay MITMProxy Script

![Untitled](https://github.com/ZhgChgLi/mitmproxy-rodo/assets/33706588/5d5ab2b2-ee07-4a37-ad31-cb60ca89713a)

**Rodo is a Python script that extends [Mitmproxy](https://mitmproxy.org) and provides a fast and easy solution for mocking an API server during client-side end-to-end testing. It eliminates the need to modify the API architecture or configure a mock server on the server-side.**

With Rodo, you can record the entire end-to-end testing process and save it as API snapshot files.
During subsequent validation tests, you can use Rodo's playback feature as a local mock API server to ensure consistent data throughout the testing phase.

By leveraging Mitmproxy and its extension capabilities, Rodo provides a seamless way to mock API servers and facilitates efficient end-to-end testing without the need for external dependencies or modifications to the existing API infrastructure.

You can customize it as needed or contribute by submitting issues or pull requests.
Thank you for your contribution and for using this project.

- ref article: [[Technical Detail][ZH-Hant] App End-to-End Testing Local Snapshot API Mock Server](https://medium.com/zrealm-ios-dev/poc-app-end-to-end-testing-local-snapshot-api-mock-server-5a5c4b25a83d)

## How It Works
Rodo is built upon the extension of Mitmproxy, utilizing a Man-in-the-Middle proxy server as an API mock server. It extends the functionality by introducing the recording and storage of responses.

In recording mode, the script captures the actual network request results and organizes them based on the path, HTTP method, and request parameters (URL query and POST form body). It generates a hash for each unique request and stores the responses in sequential order.

In playback mode, the script compares the incoming requests with the stored data. If a match (same path and same hash) is found, the corresponding local data is retrieved. If a request has been made multiple times, the script retrieves the stored data in the order they were recorded. At this point, no real network requests are made.

![image](https://github.com/ZhgChgLi/mitmproxy-rodo/assets/33706588/ae5841c5-b0d3-49ac-9ddd-c918d5484d78)


##### The save data directory structure should be as follows:
- Host
- ++ Path composed with `-` (e.g., get/user will be get-user)
- +++ HTTP Method
- ++++ Hash (Request Query + Request Form Body)
- +++++ Content-X.json (Saved Content)
- +++++ Header-X.json (Saved Header)

## Environment
Please make sure you have installed the [Mitmproxy](https://mitmproxy.org) tool and have installed and enabled the corresponding root certificate on your computer, mobile device, or emulator.

```
brew install mitmproxy
```
and [about certificates](https://docs.mitmproxy.org/stable/concepts-certificates/).

## Usage
### Regular Proxy Mode
- iOS: Set the proxy on your computer or mobile device.
- Android: Set the proxy on your emulator or mobile device.
- suggest adding `"~d xxx.com"` at the end of the command to filter only the API Host Domain.

#### Record
```
mitmdump -s rodo.py --set dumper_folder=myTestCase --set record=true 
```
#### Playback
```
mitmdump -s rodo.py --set dumper_folder=myTestCase
```

### Reverse Proxy Mode
- iOS/Android App: Change the API host parameter in the codebase to the reverse proxy server (e.g., `http://127.0.0.1:8080`).

#### Record
```
mitmdump -m reverse:https://api.zhgchg.li -s rodo.py --set dumper_folder=myTestCase --set record=true 
```
#### Playback
```
mitmdump -m reverse:https://api.zhgchg.li -s rodo.py --set dumper_folder=myTestCase
```

## Parameter List
- `--set record=true`: Default is false. Set to false for playback mode or true for recording mode. If the target directory already exists, it will be automatically cleared.
- `--set dumper_folder=output_directory`: Default is /dump. It is recommended to have one directory per test case. 
- `-—set network_restricted=true`: Default is true. Determines how to handle missing local saved data. Set to true to return 404, or false to make real requests to fetch data.
- `-—set config_file=config.json`: Path to the config.json configuration file. (The configuration information for config.json is provided below.)
- `-—set auto_extend_cookie_expire_days=7`: Default is 7. Specifies the number of days to automatically extend all cookie expires if the max-age is not set. Set to 0 to disable auto extension.
- `"~d api.zhgchg.li"`: You can add this parameter at **the end of the command** in Regular Proxy mode to filter only the required API Domain Host. ([Filter Expressions](https://docs.mitmproxy.org/stable/concepts-filters/) )

### config.json
```json
{
  "HOST NAME (support wildcard)": {
    "API Path (support wildcard)": {
      "Request HTTP Method (support wildcard)": {
        "iterable": false, // Default is False. When set to True, if there are repeated requests for the same path, only the first file will be continuously overwritten instead of creating new files.
        "enables": [ // Determines the factors to enable for hashing. Enter "query" and/or "formData" to include URL query and POST form body as part of the hash value. Enter "query" to include only the URL query as part of the hash value. Leave empty to consider only the API Path without parameters.
          "query",
          "formData"
        ],
        "rules": { // Specifies the parameters to exclude from hashing. It can exclude parameters like timestamp or parameters that may vary each time the script is run to prevent these parameters from causing different hash values and unable to find local data.
          "query": {
            "parameters": [
              "ts"
            ]
          },
          "formData": {
            "parameters": []
          }
        }
      }
    }
  }
}
```

Note: The provided JSON represents the configuration structure for the config.json file. It allows you to define rules and settings for specific host names, API paths, and request methods. You can enable hashing based on query parameters and/or form data, specify whether the same path should create new files or overwrite existing ones, and define rules to exclude certain parameters from the hashing process. Adjust these settings as needed to customize Rodo's behavior.

#### For Example
```json
{
  "ignored": {
    "api.zhgchg.li": {
      "check-online_status": {
        "GET": {
          "iterable": true
        }
      },
      "get-user": {
        "GET": {
          "iterable": false,
          "enables": [
            "query",
            "formData"
          ],
          "rules": {
            "query": {
              "parameters": [
                "created_at"
              ]
            },
            "formData": {
              "parameters": []
            }
          }
        }
      }
    },
    "*": {
      "*": {
        "*": {
          "iterable": false,
          "enables": [
            "query",
            "formData"
          ],
          "rules": {
            "query": {
              "parameters": [
                "ts"
              ]
            },
            "formData": {
              "parameters": []
            }
          }
        }
      }
    }
  }
}
```

## ToDo
- [ ] Create an iOS End-to-End Testing using the Github API and this tool as a local Mock Server.

## Inspiration
- [mitmproxy-mock](https://github.com/woltapp/mitmproxy-mock)

## Why is it called Rodo?
<img width="486" alt="image" src="https://github.com/ZhgChgLi/mitmproxy-rodo/assets/33706588/356a788d-8dc4-47f9-9dc7-b5dd678c1fdf">

It's from the Japanese anime "Jujutsu Kaisen" - a quote from the character Kento Nanami.
- 労働はクソということです (**Rōdō** wa kuso to iu kotodesu)

## Author
- [ZhgChg.Li](https://zhgchg.li/)
- [ZhgChgLi's Medium](https://blog.zhgchg.li/)

## Other works
### Swift Libraries
- [ZMarkupParser](https://github.com/ZhgChgLi/ZMarkupParser) is a pure-Swift library that helps you to convert HTML strings to NSAttributedString with customized style and tags.
- [ZPlayerCacher](https://github.com/ZhgChgLi/ZPlayerCacher) is a lightweight implementation of the AVAssetResourceLoaderDelegate protocol that enables AVPlayerItem to support caching streaming files.
- [ZNSTextAttachment](https://github.com/ZhgChgLi/ZNSTextAttachment) enables NSTextAttachment to download images from remote URLs, support both UITextView and UILabel.

### Integration Tools
- [ZReviewTender](https://github.com/ZhgChgLi/ZReviewTender) is a tool for fetching app reviews from the App Store and Google Play Console and integrating them into your workflow.
- [ZMediumToMarkdown](https://github.com/ZhgChgLi/ZMediumToMarkdown) is a powerful tool that allows you to effortlessly download and convert your Medium posts to Markdown format.

# Donate

[![Buy Me A Coffe](https://img.buymeacoffee.com/button-api/?text=Buy%20me%20a%20beer!&emoji=%F0%9F%8D%BA&slug=zhgchgli&button_colour=FFDD00&font_colour=000000&font_family=Bree&outline_colour=000000&coffee_colour=ffffff)](https://www.buymeacoffee.com/zhgchgli)

If you find this library helpful, please consider starring the repo or recommending it to your friends.

Feel free to open an issue or submit a fix/contribution via pull request. :)
