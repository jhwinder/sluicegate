namespace SluiceGate.Minion;

/// <summary>Detects a worker that keeps exiting soon after it starts, so the service can fail visibly instead of restarting forever.</summary>
public sealed class CrashLoopTracker
{
    private readonly int _limit;
    private readonly TimeSpan _healthyRuntime;

    public CrashLoopTracker(int limit = 5, TimeSpan? healthyRuntime = null)
    {
        _limit = limit;
        _healthyRuntime = healthyRuntime ?? TimeSpan.FromSeconds(60);
    }

    public int ConsecutiveRapidExits { get; private set; }

    /// <summary>Records one worker exit and returns true when the crash-loop limit has been reached.</summary>
    public bool RecordExit(TimeSpan runtime)
    {
        ConsecutiveRapidExits = runtime < _healthyRuntime ? ConsecutiveRapidExits + 1 : 0;
        return ConsecutiveRapidExits >= _limit;
    }
}
