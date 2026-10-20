// Show the service's log output in the test results; essential when diagnosing CI failures.
[assembly: CaptureConsole]

// Capture affects the whole machine (WinDivert) or the processes the tests start: one test at a time.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
