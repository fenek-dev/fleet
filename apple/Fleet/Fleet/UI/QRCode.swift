import AppKit
@preconcurrency import AVFoundation
import CoreImage.CIFilterBuiltins
import SwiftUI
import Vision

/// A QR code for `text` (the pairing code: uppercase alphanumerics).
struct QRCodeView: View {
    let text: String

    var body: some View {
        if let img = Self.image(text) {
            Image(nsImage: img)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
                .padding(12)
                .background(Color.white, in: RoundedRectangle(cornerRadius: 8))
        } else {
            Text("QR code unavailable").foregroundStyle(Color.textMuted)
        }
    }

    static func image(_ text: String) -> NSImage? {
        let f = CIFilter.qrCodeGenerator()
        f.message = Data(text.utf8)
        f.correctionLevel = "M"
        guard let out = f.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)) else { return nil }
        let rep = NSCIImageRep(ciImage: out)
        let img = NSImage(size: rep.size)
        img.addRepresentation(rep)
        return img
    }
}

/// Camera preview that reports the first `FLEETPAIR1-` QR code it sees
/// (AVFoundation capture, Vision barcode detection; macOS has no
/// `AVCaptureMetadataOutput`). Needs camera permission
/// (`NSCameraUsageDescription`, `com.apple.security.device.camera`).
struct QRScannerView: NSViewRepresentable {
    let onCode: @MainActor (String) -> Void

    func makeNSView(context: Context) -> ScannerNSView {
        let v = ScannerNSView()
        v.onCode = onCode
        v.start()
        return v
    }

    func updateNSView(_ view: ScannerNSView, context: Context) {}

    static func dismantleNSView(_ view: ScannerNSView, coordinator: ()) {
        view.stop()
    }
}

final class ScannerNSView: NSView {
    var onCode: (@MainActor (String) -> Void)?
    private let scanner = QRScanner()

    func start() {
        wantsLayer = true
        scanner.onCode = { [weak self] code in
            Task { @MainActor in self?.onCode?(code) }
        }
        Task { @MainActor [weak self] in
            guard let self, await self.scanner.start() else { return }
            let preview = AVCaptureVideoPreviewLayer(session: self.scanner.session)
            preview.videoGravity = .resizeAspectFill
            preview.frame = self.bounds
            preview.autoresizingMask = [.layerWidthSizable, .layerHeightSizable]
            self.layer?.addSublayer(preview)
        }
    }

    func stop() {
        scanner.stop()
    }
}

/// Capture pipeline; frames are analyzed on its own queue.
final class QRScanner: NSObject, AVCaptureVideoDataOutputSampleBufferDelegate, @unchecked Sendable {
    let session = AVCaptureSession()
    var onCode: (@Sendable (String) -> Void)?
    private let queue = DispatchQueue(label: "dev.fleet.qr")
    private var found = false

    /// Asks for camera access and starts; `false` if denied or no camera.
    func start() async -> Bool {
        let granted: Bool
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized: granted = true
        case .notDetermined: granted = await AVCaptureDevice.requestAccess(for: .video)
        default: granted = false
        }
        guard granted, let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device)
        else { return false }
        session.beginConfiguration()
        if session.canAddInput(input) { session.addInput(input) }
        let output = AVCaptureVideoDataOutput()
        output.setSampleBufferDelegate(self, queue: queue)
        if session.canAddOutput(output) { session.addOutput(output) }
        session.commitConfiguration()
        queue.async { [self] in session.startRunning() }
        return true
    }

    func stop() {
        queue.async { [self] in session.stopRunning() }
    }

    func captureOutput(_ output: AVCaptureOutput, didOutput buffer: CMSampleBuffer, from connection: AVCaptureConnection) {
        guard !found, let pixels = CMSampleBufferGetImageBuffer(buffer) else { return }
        let req = VNDetectBarcodesRequest()
        req.symbologies = [.qr]
        try? VNImageRequestHandler(cvPixelBuffer: pixels, options: [:]).perform([req])
        for r in req.results ?? [] {
            if let s = r.payloadStringValue, s.hasPrefix("FLEETPAIR1-") {
                found = true
                onCode?(s)
                return
            }
        }
    }
}
