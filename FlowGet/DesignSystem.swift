import SwiftUI

enum FlowPalette {
    static let background = Color("FlowBackground")
    static let surface = Color("FlowSurface")
    static let inset = Color("FlowInset")
    static let selected = Color("FlowSelected")
    static let content = Color.primary
    static let secondary = Color.secondary
    static let outline = Color("FlowOutline")
    static let action = Color("FlowAction")
    static let onAction = Color("FlowOnAction")
    static let success = Color(red: 0.15, green: 0.55, blue: 0.34)
    static let danger = Color(red: 0.78, green: 0.31, blue: 0.31)
}

struct FlowGetLogo: View {
    var size: CGFloat = 52

    var body: some View {
        Image("FlowGetMark")
            .renderingMode(.template)
            .resizable()
            .scaledToFit()
            .foregroundStyle(FlowPalette.content)
            .frame(width: size, height: size)
    }
}

struct FlowCard<Content: View>: View {
    let content: Content
    var body: some View {
        content
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(FlowPalette.surface)
            .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(FlowPalette.outline, lineWidth: 0.7))
            .shadow(color: .black.opacity(0.07), radius: 3, y: 2)
    }
}

struct FlowIcon: View {
    let name: String
    var emphasized = false
    var body: some View {
        Image(systemName: name)
            .font(.system(size: 21, weight: .semibold))
            .frame(width: 52, height: 52)
            .background(emphasized ? FlowPalette.selected : FlowPalette.inset)
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
    }
}

struct FlowSectionTitle: View {
    let title: String
    var body: some View {
        Text(title).font(.title3.bold()).frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct FlowPrimaryButton: View {
    let title: String
    var icon: String?
    var disabled = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack {
                if let icon { Image(systemName: icon) }
                Text(title).fontWeight(.semibold)
            }
            .frame(maxWidth: .infinity, minHeight: 52)
            .foregroundStyle(FlowPalette.onAction)
            .background(disabled ? FlowPalette.action.opacity(0.45) : FlowPalette.action)
            .clipShape(RoundedRectangle(cornerRadius: 16))
        }
        .disabled(disabled)
    }
}

struct FlowTopBar: View {
    let title: String
    var onMenu: (() -> Void)?
    var trailing: AnyView?
    var body: some View {
        HStack(spacing: 16) {
            if let onMenu {
                Button(action: onMenu) { Image(systemName: "line.3.horizontal").font(.title2.bold()) }
            }
            Text(title).font(.largeTitle.bold())
            Spacer()
            trailing
        }
        .foregroundStyle(FlowPalette.content)
        .padding(.horizontal, 20)
        .padding(.top, 10)
        .padding(.bottom, 12)
    }
}

extension View {
    func flowPage() -> some View { background(FlowPalette.background.ignoresSafeArea()) }
}
