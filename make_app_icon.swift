import AppKit
import Foundation

let output = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.iconset"
let fm = FileManager.default
try? fm.removeItem(atPath: output)
try fm.createDirectory(atPath: output, withIntermediateDirectories: true)
func color(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> NSColor { NSColor(calibratedRed:r, green:g, blue:b, alpha:a) }
func drawIcon(size: Int, path: String) throws {
    guard let bitmap = NSBitmapImageRep(bitmapDataPlanes:nil, pixelsWide:size, pixelsHigh:size, bitsPerSample:8, samplesPerPixel:4, hasAlpha:true, isPlanar:false, colorSpaceName:.deviceRGB, bytesPerRow:0, bitsPerPixel:0), let context = NSGraphicsContext(bitmapImageRep:bitmap) else { throw NSError(domain:"IOTAIcon", code:1) }
    NSGraphicsContext.saveGraphicsState(); NSGraphicsContext.current=context; context.imageInterpolation = .high
    context.cgContext.scaleBy(x:CGFloat(size)/1024, y:CGFloat(size)/1024)
    color(0.008,0.025,0.014).setFill(); NSBezierPath(rect:NSRect(x:0,y:0,width:1024,height:1024)).fill()
    let base=NSBezierPath(roundedRect:NSRect(x:42,y:42,width:940,height:940),xRadius:210,yRadius:210)
    NSGradient(colors:[color(0.012,0.075,0.032),color(0.003,0.018,0.009)])!.draw(in:base,angle:-45)
    color(0.18,1.0,0.38,0.65).setStroke(); base.lineWidth=10; base.stroke()
    let tile=NSBezierPath(roundedRect:NSRect(x:342,y:496,width:340,height:340),xRadius:72,yRadius:72)
    NSGradient(colors:[color(0.42,1.0,0.57),color(0.06,0.72,0.24)])!.draw(in:tile,angle:-45)
    color(0.015,0.09,0.035,0.45).setStroke(); tile.lineWidth=7; tile.stroke()
    let label="TAH" as NSString, font=NSFont.monospacedSystemFont(ofSize:190,weight:.heavy)
    let attrs:[NSAttributedString.Key:Any]=[.font:font,.foregroundColor:color(0.005,0.055,0.02),.kern:4.0]
    label.draw(at:NSPoint(x:(1024-label.size(withAttributes:attrs).width)/2,y:585),withAttributes:attrs)
    let sub="IOTA TRAIN AT HOME" as NSString, subFont=NSFont.monospacedSystemFont(ofSize:39,weight:.semibold)
    let subAttrs:[NSAttributedString.Key:Any]=[.font:subFont,.foregroundColor:color(0.34,1.0,0.5),.kern:4.0]
    sub.draw(at:NSPoint(x:(1024-sub.size(withAttributes:subAttrs).width)/2,y:352),withAttributes:subAttrs)
    color(0.15,0.9,0.34,0.72).setFill()
    for (x,y,h) in [(204,678,84),(260,738,48),(760,700,92),(817,654,52),(212,282,45),(804,278,70)] { NSBezierPath(roundedRect:NSRect(x:x,y:y,width:8,height:h),xRadius:4,yRadius:4).fill() }
    context.flushGraphics(); NSGraphicsContext.restoreGraphicsState()
    guard let data=bitmap.representation(using:.png,properties:[:]) else { throw NSError(domain:"IOTAIcon",code:2) }
    try data.write(to:URL(fileURLWithPath:path))
}
let images:[(String,Int)]=[("icon_16x16.png",16),("icon_16x16@2x.png",32),("icon_32x32.png",32),("icon_32x32@2x.png",64),("icon_128x128.png",128),("icon_128x128@2x.png",256),("icon_256x256.png",256),("icon_256x256@2x.png",512),("icon_512x512.png",512),("icon_512x512@2x.png",1024)]
for (name,size) in images { try drawIcon(size:size,path:"\(output)/\(name)") }
