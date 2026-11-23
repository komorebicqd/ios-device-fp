import SwiftUI
import DeviceFingerprintSDK

@main
struct FingerprintDemoApp: App {

    init() {
        FingerprintSDK.configure(
            appId: DemoConfig.defaultAppId,
            baseURL: DemoConfig.defaultBaseURL
        )
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

enum DemoConfig {
    static let defaultAppId = "demo-app-id"
    /// 模拟器直接用本机地址；真机改成 Mac 的局域网地址，例如 http://192.168.1.10:8080
    static let defaultBaseURL = "http://127.0.0.1:8080"
}
