import BackgroundTasks
import Foundation

enum BackgroundScheduler {
    static let identifier = "com.flowget.ios.scheduled-downloads"
    @MainActor static var runQueuedDownloads: (() -> Void)?

    static func register() {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: identifier, using: nil) { task in
            guard let processingTask = task as? BGProcessingTask else {
                task.setTaskCompleted(success: false)
                return
            }
            processingTask.expirationHandler = {}
            Task { @MainActor in
                runQueuedDownloads?()
                processingTask.setTaskCompleted(success: true)
            }
        }
    }

    static func reschedule(_ schedules: [DownloadSchedule], now: Date = Date()) {
        BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: identifier)
        guard let nextDate = nextRunDate(for: schedules, now: now) else { return }
        let request = BGProcessingTaskRequest(identifier: identifier)
        request.earliestBeginDate = nextDate
        request.requiresNetworkConnectivity = true
        request.requiresExternalPower = false
        try? BGTaskScheduler.shared.submit(request)
    }

    static func nextRunDate(for schedules: [DownloadSchedule], now: Date = Date(), calendar: Calendar = .current) -> Date? {
        let enabled = schedules.filter { $0.enabled && !$0.weekdays.isEmpty }
        return enabled.compactMap { schedule in
            (0...7).compactMap { dayOffset -> Date? in
                guard let day = calendar.date(byAdding: .day, value: dayOffset, to: now) else { return nil }
                let weekday = calendar.component(.weekday, from: day)
                guard schedule.weekdays.contains(weekday) else { return nil }
                var components = calendar.dateComponents([.year, .month, .day], from: day)
                components.hour = schedule.hour
                components.minute = schedule.minute
                components.second = 0
                guard let candidate = calendar.date(from: components), candidate > now else { return nil }
                return candidate
            }.min()
        }.min()
    }
}
