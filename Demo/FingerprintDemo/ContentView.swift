import SwiftUI
import DeviceFingerprintSDK

struct ContentView: View {

    @State private var appId = DemoConfig.defaultAppId
    @State private var baseURL = DemoConfig.defaultBaseURL
    @State private var logs: [LogEntry] = []
    @State private var isRunning = false

    var body: some View {
        NavigationStack {
            Form {
                Section("服务端配置") {
                    TextField("appId", text: $appId)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("baseURL", text: $baseURL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                    Button("应用配置") {
                        applyConfiguration()
                    }
                }

                Section("获取 deviceId") {
                    Button("获取一次") {
                        fetchOnce()
                    }
                    Button("并发获取 10 次（验证单飞）") {
                        fetchConcurrently()
                    }
                    Button("重置内存缓存") {
                        FingerprintSDK.reset()
                        append("已重置内存缓存；Keychain 中的 deviceId 仍然保留")
                    }
                }
                .disabled(isRunning)

                Section("日志") {
                    if logs.isEmpty {
                        Text("暂无日志")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(logs) { entry in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(entry.time)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                            Text(entry.text)
                                .font(.footnote)
                                .textSelection(.enabled)
                        }
                    }
                }

                Section("说明") {
                    Text("真机联调：把 baseURL 改成 Mac 的局域网地址（如 http://192.168.1.10:8080），手机与 Mac 处于同一 Wi-Fi，并在系统弹窗中允许「本地网络」权限。")
                        .font(.footnote)
                    Text("卸载重装后 deviceId 应保持不变（Keychain 持久化）；首次联网前日志里会看到一次完整的 init → generate 链路。")
                        .font(.footnote)
                    Button("清空日志") {
                        logs.removeAll()
                    }
                }
            }
            .navigationTitle("设备指纹 Demo")
        }
    }

    // MARK: - Actions

    private func applyConfiguration() {
        FingerprintSDK.configure(appId: appId, baseURL: baseURL)
        append("已应用配置：appId=\(appId)，baseURL=\(baseURL)")
    }

    private func fetchOnce() {
        isRunning = true
        let start = Date()

        FingerprintSDK.getDeviceId { result in
            let elapsed = Int(Date().timeIntervalSince(start) * 1000)
            DispatchQueue.main.async {
                isRunning = false
                switch result {
                case .success(let deviceId):
                    append("成功：\(deviceId)（\(elapsed) ms）")
                case .failure(let error):
                    append("失败：\(error.localizedDescription)")
                }
            }
        }
    }

    private func fetchConcurrently() {
        isRunning = true
        let start = Date()
        let group = DispatchGroup()
        let lock = NSLock()
        var outcomes: [String] = []

        for _ in 0..<10 {
            group.enter()
            FingerprintSDK.getDeviceId { result in
                lock.lock()
                switch result {
                case .success(let deviceId):
                    outcomes.append(deviceId)
                case .failure(let error):
                    outcomes.append("error:\(error.localizedDescription)")
                }
                lock.unlock()
                group.leave()
            }
        }

        group.notify(queue: .main) {
            isRunning = false
            let elapsed = Int(Date().timeIntervalSince(start) * 1000)
            append("并发完成：\(outcomes.count) 个结果，唯一值 \(Set(outcomes).count) 个，总耗时 \(elapsed) ms")
        }
    }

    private func append(_ text: String) {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        logs.insert(LogEntry(time: formatter.string(from: Date()), text: text), at: 0)
    }
}

struct LogEntry: Identifiable {
    let id = UUID()
    let time: String
    let text: String
}
