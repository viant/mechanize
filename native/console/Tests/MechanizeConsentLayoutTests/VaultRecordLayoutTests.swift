import XCTest
import AppKit
import SwiftUI
@testable import MechanizeConsent

@MainActor private final class LegacyRecordInput:ObservableObject {
    struct Field:Identifiable {let id=UUID();var name="";var value=""}
    @Published var key="";@Published var fields=[Field()]
}
@MainActor private struct LegacyRecordLayout: View {
    @ObservedObject var input:LegacyRecordInput
    var body:some View {
        VStack(alignment:.leading,spacing:16){
            Text("Create secret").font(.title2)
            Text("Choose any key and add named secret fields. Keys, names, and values are encrypted locally.")
            ScrollView {VStack(alignment:.leading,spacing:12){
                SecureField("Secret key",text:$input.key)
                ForEach($input.fields){$field in HStack{SecureField("Field name",text:$field.name);SecureField("Field value",text:$field.value);Button("Remove") {}}}
            }}.frame(maxHeight:260)
            Button("Add field"){input.fields.append(.init())}
            Text("Up to 32 fields. No website permission is granted by storing this record.").font(.caption)
            HStack{Button("Cancel"){};Button("Encrypt and save") {}}
        }.padding(24).frame(width:500)
    }
}
@MainActor final class VaultRecordLayoutTests:XCTestCase {
    func testLegacyPlaceholderReproducesCollapsedViewport() throws {
        _=NSApplication.shared
        let input=LegacyRecordInput(),window=NSWindow(contentRect:NSRect(x:-10000,y:-10000,width:520,height:480),styleMask:[.titled,.closable],backing:.buffered,defer:false)
        window.isReleasedWhenClosed=false;defer{window.contentView=nil;window.close()}
        let placeholder=NSHostingView(rootView:Text("Preparing protected entry…").padding(24));window.contentView=placeholder
        settle(placeholder)
        XCTAssertLessThan(placeholder.frame.height,100)
        let host=NSHostingView(rootView:LegacyRecordLayout(input:input));window.contentView=host
        settle(host)
        let secure=descendants(host).compactMap{$0 as? NSSecureTextField}
        let scroll=descendants(host).compactMap{$0 as? NSScrollView}
        XCTAssertLessThan(try XCTUnwrap(scroll.first).contentView.bounds.height,2)
        XCTAssertEqual(secure.count,3)
    }
    func testTypedFieldsKeepUsableViewportAfterPreparingAndShowEveryBasicControl() throws {
        _=NSApplication.shared
        let input=VaultRecordInput(),window=NSWindow(contentRect:NSRect(origin:NSPoint(x:-10000,y:-10000),size:VaultRecordLayout.size(forDeletion:false)),styleMask:[.titled,.closable],backing:.buffered,defer:false)
        window.isReleasedWhenClosed=false;defer{window.contentView=nil;window.close()}
        VaultRecordLayout.install(Text("Preparing protected entry…").padding(24),in:window,forDeletion:false)
        settle(try XCTUnwrap(window.contentView))
        XCTAssertEqual(window.contentView?.frame.height,620)
        VaultRecordLayout.install(VaultRecordFields(input:input).padding(24),in:window,forDeletion:false)
        let host=try XCTUnwrap(window.contentView);settle(host)
        XCTAssertEqual(descendants(host).compactMap{$0 as? NSSecureTextField}.count,2)
        input.selectType(.basic);settle(host)
        let secure=descendants(host).compactMap{$0 as? NSSecureTextField},scroll=try XCTUnwrap(descendants(host).compactMap{$0 as? NSScrollView}.first)
        XCTAssertEqual(secure.count,5);XCTAssertGreaterThanOrEqual(scroll.contentView.bounds.height,270)
        XCTAssertTrue(secure.allSatisfy{$0.frame.height>=20 && $0.frame.width>100})
        let document=try XCTUnwrap(scroll.documentView)
        for field in secure {let rectangle=field.convert(field.bounds,to:document);XCTAssertGreaterThanOrEqual(rectangle.intersection(scroll.contentView.documentVisibleRect).height,20)}
        input.selectType(.jwt);settle(host)
        XCTAssertEqual(descendants(host).compactMap{$0 as? NSSecureTextField}.count,2)
        XCTAssertGreaterThanOrEqual(try XCTUnwrap(descendants(host).compactMap{$0 as? NSScrollView}.first).contentView.bounds.height,270)
    }
    private func descendants(_ view:NSView)->[NSView]{view.subviews.flatMap{[$0]+descendants($0)}}
    private func settle(_ view:NSView){for _ in 0..<5 {view.layoutSubtreeIfNeeded();RunLoop.main.run(until:Date().addingTimeInterval(0.02))}}
}
