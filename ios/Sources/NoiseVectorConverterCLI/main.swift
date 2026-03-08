import Foundation
import NoiseTestHarness

struct ConversionRequest {
    let inputURL: URL
    let outputDirectoryURL: URL
    let schemaPath: String
}

enum ConversionCLIError: Error, CustomStringConvertible {
    case invalidArguments(String)

    var description: String {
        switch self {
        case .invalidArguments(let message):
            return message
        }
    }
}

@main
struct NoiseVectorConverterCLI {
    static func main() async {
        do {
            let request = try parse(arguments: Array(CommandLine.arguments.dropFirst()))
            let document = try String(contentsOf: request.inputURL, encoding: .utf8)
            let urls = try await OfficialNoiseVectorConverter().convertDocument(
                document,
                outputDirectory: request.outputDirectoryURL,
                schemaPath: request.schemaPath
            )

            print("Wrote \(urls.count) shared Noise fixture(s):")
            for url in urls {
                print(url.path)
            }
        } catch {
            fputs("\(error)\n", stderr)
            Foundation.exit(1)
        }
    }

    private static func parse(arguments: [String]) throws -> ConversionRequest {
        var input: String?
        var output: String?
        var schemaPath = NoiseVectorFixtureWriter.defaultSchemaPath

        var index = 0
        while index < arguments.count {
            switch arguments[index] {
            case "--input":
                index += 1
                input = try value(arguments, at: index, for: "--input")
            case "--output-dir":
                index += 1
                output = try value(arguments, at: index, for: "--output-dir")
            case "--schema-path":
                index += 1
                schemaPath = try value(arguments, at: index, for: "--schema-path")
            default:
                throw ConversionCLIError.invalidArguments(
                    "Unknown argument '\(arguments[index])'. Supported arguments: --input <path> --output-dir <path> [--schema-path <path>]."
                )
            }
            index += 1
        }

        guard let input else {
            throw ConversionCLIError.invalidArguments("Missing required argument --input <path>.")
        }
        guard let output else {
            throw ConversionCLIError.invalidArguments("Missing required argument --output-dir <path>.")
        }

        return ConversionRequest(
            inputURL: URL(fileURLWithPath: input),
            outputDirectoryURL: URL(fileURLWithPath: output, isDirectory: true),
            schemaPath: schemaPath
        )
    }

    private static func value(_ arguments: [String], at index: Int, for flag: String) throws -> String {
        guard index < arguments.count else {
            throw ConversionCLIError.invalidArguments("Argument \(flag) requires a value.")
        }
        return arguments[index]
    }
}