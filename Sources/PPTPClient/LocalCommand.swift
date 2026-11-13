import Dispatch
import Darwin
import Foundation
import PPTPCore

enum LocalCommand {
    /// Fixed executable paths and argument arrays; no shell interpolation.
    static func run(_ path: String, _ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        let done = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in done.signal() }
        try process.run()
        guard done.wait(timeout: .now() + 3) == .success else {
            process.terminate()
            if done.wait(timeout: .now() + 1) != .success {
                kill(process.processIdentifier, SIGKILL)
                _ = done.wait(timeout: .now() + 1)
            }
            throw PPTPError("local network configuration command timed out")
        }
        guard process.terminationStatus == 0 else {
            let text = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            let safe = text.unicodeScalars.map { CharacterSet.controlCharacters.contains($0) ? " " : String($0) }.joined()
            throw PPTPError("\(URL(fileURLWithPath: path).lastPathComponent) failed: \(safe.prefix(500))")
        }
    }
}
