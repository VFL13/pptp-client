import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

let size = 1024
let colorSpace = CGColorSpaceCreateDeviceRGB()
guard let context = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: size * 4,
                              space: colorSpace, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { fatalError("context") }
let rect = CGRect(x: 64, y: 64, width: 896, height: 896)
context.addPath(CGPath(roundedRect: rect, cornerWidth: 205, cornerHeight: 205, transform: nil))
context.clip()
let colors = [CGColor(red: 0.04, green: 0.48, blue: 0.92, alpha: 1), CGColor(red: 0.08, green: 0.16, blue: 0.48, alpha: 1)] as CFArray
let gradient = CGGradient(colorsSpace: colorSpace, colors: colors, locations: [0, 1])!
context.drawLinearGradient(gradient, start: CGPoint(x: 180, y: 930), end: CGPoint(x: 850, y: 100), options: [])
let points = [CGPoint(x: 285, y: 340), CGPoint(x: 739, y: 340), CGPoint(x: 512, y: 715)]
context.setStrokeColor(CGColor(gray: 1, alpha: 0.9)); context.setLineWidth(28); context.setLineCap(.round)
context.move(to: points[0]); context.addLine(to: points[1]); context.addLine(to: points[2]); context.addLine(to: points[0]); context.strokePath()
for point in points {
    context.setFillColor(CGColor(gray: 1, alpha: 1))
    context.fillEllipse(in: CGRect(x: point.x - 62, y: point.y - 62, width: 124, height: 124))
    context.setFillColor(CGColor(red: 0.08, green: 0.30, blue: 0.67, alpha: 1))
    context.fillEllipse(in: CGRect(x: point.x - 24, y: point.y - 24, width: 48, height: 48))
}
let url = URL(fileURLWithPath: CommandLine.arguments[1])
guard let image = context.makeImage(), let destination = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil) else { fatalError("image") }
CGImageDestinationAddImage(destination, image, nil)
guard CGImageDestinationFinalize(destination) else { fatalError("write") }
