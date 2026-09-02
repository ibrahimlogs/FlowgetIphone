import SwiftUI
import UIKit

enum FlowPalette {
    static let background = Color("FlowBackground")
    static let surface = Color("FlowSurface")
    static let inset = Color("FlowInset")
    static let selected = Color("FlowSelected")
    static let outline = Color("FlowOutline")
    static let action = Color("FlowAction")
    static let onAction = Color("FlowOnAction")

    static let elevated = adaptive(light: 0xFCFCFD, dark: 0x202327)
    static let content = adaptive(light: 0x111214, dark: 0xF2F2F0)
    static let secondary = adaptive(light: 0x5E636A, dark: 0xB0B4B9)
    static let tertiary = adaptive(light: 0x858A91, dark: 0x7E848B)
    static let progressTrack = adaptive(light: 0xDDE0E3, dark: 0x34383D)
    static let success = adaptive(light: 0x278D56, dark: 0x65BE88)
    static let danger = adaptive(light: 0xC84F4F, dark: 0xE07A7A)
    static let warning = adaptive(light: 0xAA7726, dark: 0xD2A45C)

    private static func adaptive(light: UInt32, dark: UInt32) -> Color {
        Color(uiColor: UIColor { traits in
            UIColor(rgb: traits.userInterfaceStyle == .dark ? dark : light)
        })
    }
}

private extension UIColor {
    convenience init(rgb: UInt32) {
        self.init(
            red: CGFloat((rgb >> 16) & 0xff) / 255,
            green: CGFloat((rgb >> 8) & 0xff) / 255,
            blue: CGFloat(rgb & 0xff) / 255,
            alpha: 1
        )
    }
}

enum FlowSpacing {
    static let xs: CGFloat = 4
    static let sm: CGFloat = 8
    static let md: CGFloat = 12
    static let lg: CGFloat = 16
    static let xl: CGFloat = 20
    static let xxl: CGFloat = 24
    static let huge: CGFloat = 32
}

enum FlowRadius {
    static let small: CGFloat = 10
    static let medium: CGFloat = 14
    static let large: CGFloat = 18
    static let extraLarge: CGFloat = 24
}

enum FlowMotion {
    static let quick = Animation.easeOut(duration: 0.15)
    static let standard = Animation.easeInOut(duration: 0.20)
    static let deliberate = Animation.easeInOut(duration: 0.25)
}

extension Font {
    static let flowDisplay = Font.custom("Product Sans", size: 34).weight(.bold)
    static let flowHeadline = Font.custom("Product Sans", size: 26).weight(.bold)
    static let flowTitleLarge = Font.custom("Product Sans", size: 22).weight(.semibold)
    static let flowTitle = Font.custom("Product Sans", size: 15).weight(.semibold)
    static let flowTitleSmall = Font.custom("Product Sans", size: 14).weight(.semibold)
    static let flowBody = Font.custom("Product Sans", size: 15)
    static let flowBodySmall = Font.custom("Product Sans", size: 13)
    static let flowCaption = Font.custom("Product Sans", size: 12)
    static let flowLabel = Font.custom("Product Sans", size: 11).weight(.medium)
    static let flowLabelSmall = Font.custom("Product Sans", size: 10).weight(.medium)
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
            .accessibilityHidden(true)
    }
}

struct FlowCard<Content: View>: View {
    let content: Content
    var elevated = false

    var body: some View {
        content
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(elevated ? FlowPalette.elevated : FlowPalette.surface)
            .clipShape(RoundedRectangle(cornerRadius: FlowRadius.large, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: FlowRadius.large, style: .continuous)
                    .stroke(FlowPalette.outline.opacity(0.65), lineWidth: 0.75)
            }
            .shadow(color: .black.opacity(elevated ? 0.08 : 0.035), radius: elevated ? 4 : 2, y: elevated ? 2 : 1)
    }
}

struct FlowIcon: View {
    let name: String
    var emphasized = false
    var size: CGFloat = 42

    var body: some View {
        Image(systemName: name)
            .font(.system(size: size * 0.48, weight: .medium))
            .foregroundStyle(FlowPalette.content)
            .frame(width: size, height: size)
            .background(emphasized ? FlowPalette.selected : FlowPalette.inset)
            .clipShape(RoundedRectangle(cornerRadius: FlowRadius.medium, style: .continuous))
            .accessibilityHidden(true)
    }
}

struct FlowSectionTitle: View {
    let title: String
    var count: Int?

    var body: some View {
        HStack(spacing: 8) {
            Text(title).font(.flowTitle).foregroundStyle(FlowPalette.content)
            if let count {
                Text("\(count)")
                    .font(.flowLabelSmall)
                    .foregroundStyle(FlowPalette.secondary)
                    .padding(.horizontal, 8)
                    .frame(height: 22)
                    .background(FlowPalette.inset)
                    .clipShape(Capsule())
            }
            Spacer(minLength: 0)
        }
    }
}

struct FlowStatusBadge: View {
    let title: String
    var color = FlowPalette.success

    var body: some View {
        Text(title)
            .font(.flowLabel)
            .foregroundStyle(color)
            .padding(.horizontal, 10)
            .frame(height: 28)
            .background(color.opacity(0.13))
            .clipShape(Capsule())
    }
}

struct FlowPrimaryButton: View {
    let title: String
    var icon: String?
    var disabled = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                if let icon { Image(systemName: icon).font(.system(size: 17, weight: .semibold)) }
                Text(title).font(.flowTitle)
            }
            .frame(maxWidth: .infinity, minHeight: 50)
            .foregroundStyle(disabled ? FlowPalette.secondary : FlowPalette.onAction)
            .background(disabled ? FlowPalette.inset : FlowPalette.action)
            .clipShape(RoundedRectangle(cornerRadius: FlowRadius.medium, style: .continuous))
        }
        .buttonStyle(FlowPressButtonStyle())
        .disabled(disabled)
    }
}

struct FlowOutlineButton: View {
    let title: String
    var icon: String?
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                if let icon { Image(systemName: icon).font(.system(size: 17, weight: .semibold)) }
                Text(title).font(.flowTitle)
            }
            .foregroundStyle(FlowPalette.content)
            .frame(maxWidth: .infinity, minHeight: 48)
            .background(FlowPalette.surface)
            .clipShape(RoundedRectangle(cornerRadius: FlowRadius.medium, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: FlowRadius.medium, style: .continuous)
                    .stroke(FlowPalette.outline, lineWidth: 1)
            }
        }
        .buttonStyle(FlowPressButtonStyle())
    }
}

struct FlowTabs: View {
    let labels: [String]
    @Binding var selection: Int

    var body: some View {
        HStack(spacing: 4) {
            ForEach(labels.indices, id: \.self) { index in
                Button {
                    withAnimation(FlowMotion.deliberate) { selection = index }
                } label: {
                    Text(labels[index])
                        .font(.flowTitle)
                        .foregroundStyle(selection == index ? FlowPalette.content : FlowPalette.tertiary)
                        .scaleEffect(selection == index ? 1 : 0.97)
                        .frame(maxWidth: .infinity, minHeight: 34)
                        .background(selection == index ? FlowPalette.elevated : .clear)
                        .clipShape(RoundedRectangle(cornerRadius: FlowRadius.small, style: .continuous))
                        .shadow(color: selection == index ? .black.opacity(0.08) : .clear, radius: 2, y: 1)
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(selection == index ? .isSelected : [])
            }
        }
        .padding(4)
        .frame(height: 42)
        .background(FlowPalette.inset)
        .clipShape(RoundedRectangle(cornerRadius: FlowRadius.medium, style: .continuous))
    }
}

struct FlowTopBar: View {
    let title: String
    var onMenu: (() -> Void)?
    var leadingIcon = "line.3.horizontal"
    var trailing: AnyView?

    var body: some View {
        HStack(spacing: 12) {
            if let onMenu {
                Button(action: onMenu) {
                    Image(systemName: leadingIcon)
                        .font(.system(size: 22, weight: .semibold))
                        .frame(width: 42, height: 42)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(leadingIcon == "chevron.left" ? "Back" : "Menu")
            }
            Text(title)
                .font(.flowHeadline)
                .foregroundStyle(FlowPalette.content)
                .lineLimit(1)
            Spacer(minLength: 8)
            if let trailing { trailing }
        }
        .foregroundStyle(FlowPalette.content)
        .padding(.horizontal, 14)
        .frame(height: 62)
        .background(FlowPalette.background)
    }
}

struct FlowProgressBar: View {
    let value: Double

    var body: some View {
        GeometryReader { geometry in
            ZStack(alignment: .leading) {
                Capsule().fill(FlowPalette.progressTrack)
                Capsule()
                    .fill(FlowPalette.content)
                    .frame(width: geometry.size.width * min(1, max(0, value)))
                    .animation(FlowMotion.deliberate, value: value)
            }
        }
        .frame(height: 5)
    }
}

struct FlowEmptyState: View {
    let image: String
    let title: String
    let message: String
    var primaryTitle: String?
    var primaryAction: (() -> Void)?
    var secondaryTitle: String?
    var secondaryIcon: String?
    var secondaryAction: (() -> Void)?

    var body: some View {
        VStack(spacing: 0) {
            Image(image)
                .resizable()
                .scaledToFit()
                .frame(maxWidth: 250, maxHeight: 220)
                .accessibilityHidden(true)
            VStack(spacing: 6) {
                Text(title).font(.flowTitleLarge).foregroundStyle(FlowPalette.content)
                Text(message)
                    .font(.flowBodySmall)
                    .foregroundStyle(FlowPalette.secondary)
                    .multilineTextAlignment(.center)
                if primaryTitle != nil || secondaryTitle != nil {
                    HStack(spacing: 10) {
                        if let primaryTitle, let primaryAction {
                            Button(primaryTitle, action: primaryAction)
                                .font(.flowTitleSmall)
                                .foregroundStyle(FlowPalette.onAction)
                                .padding(.horizontal, 15)
                                .frame(height: 46)
                                .background(FlowPalette.action)
                                .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                                .buttonStyle(FlowPressButtonStyle())
                        }
                        if let secondaryTitle, let secondaryAction {
                            Button(action: secondaryAction) {
                                HStack(spacing: 6) {
                                    if let secondaryIcon { Image(systemName: secondaryIcon) }
                                    Text(secondaryTitle)
                                }
                                .font(.flowTitleSmall)
                                .foregroundStyle(FlowPalette.content)
                                .padding(.horizontal, 13)
                                .frame(height: 46)
                                .background(FlowPalette.surface)
                                .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                                .overlay(RoundedRectangle(cornerRadius: 12).stroke(FlowPalette.outline))
                            }
                            .buttonStyle(FlowPressButtonStyle())
                        }
                    }
                    .padding(.top, 14)
                }
            }
            .offset(y: -22)
        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 24)
    }
}

struct FlowPressButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
            .opacity(configuration.isPressed ? 0.88 : 1)
            .animation(FlowMotion.quick, value: configuration.isPressed)
    }
}

struct FlowSwitchToggleStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        Button {
            withAnimation(FlowMotion.standard) { configuration.isOn.toggle() }
        } label: {
            ZStack(alignment: configuration.isOn ? .trailing : .leading) {
                Capsule().fill(configuration.isOn ? FlowPalette.action : FlowPalette.progressTrack)
                Circle()
                    .fill(configuration.isOn ? FlowPalette.onAction : FlowPalette.surface)
                    .padding(3)
                    .shadow(color: .black.opacity(0.12), radius: 1, y: 1)
            }
            .frame(width: 46, height: 30)
        }
        .buttonStyle(.plain)
        .accessibilityValue(configuration.isOn ? "On" : "Off")
    }
}

extension View {
    func flowPage() -> some View {
        foregroundStyle(FlowPalette.content)
            .background(FlowPalette.background.ignoresSafeArea())
    }
}
