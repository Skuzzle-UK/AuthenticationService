using System.Data.Common;
using Microsoft.EntityFrameworkCore.Storage;

namespace AuthenticationService.Storage;

/// <summary>
/// Retries transient MySQL errors with exponential backoff. Oracle's
/// <c>MySql.EntityFrameworkCore</c> doesn't ship a <c>EnableRetryOnFailure</c>
/// equivalent, so we plug in our own predicate. Remove when we migrate to Pomelo 10.
/// </summary>
public sealed class MySqlRetryingExecutionStrategy : ExecutionStrategy
{
    public const int MaxRetryAttempts = 5;
    public static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(30);

    public MySqlRetryingExecutionStrategy(ExecutionStrategyDependencies dependencies)
        : base(dependencies, MaxRetryAttempts, MaxBackoff)
    {
    }

    // Test-friendly overload — lets tests pick count/delay deterministically.
    internal MySqlRetryingExecutionStrategy(
        ExecutionStrategyDependencies dependencies,
        int maxRetryCount,
        TimeSpan maxRetryDelay)
        : base(dependencies, maxRetryCount, maxRetryDelay)
    {
    }

    protected override bool ShouldRetryOn(Exception exception) =>
        IsTransientDatabaseError(exception);

    // Walks the inner-exception chain — EF often wraps provider exceptions in
    // DbUpdateException, so a top-level check would miss the real cause.
    // internal so tests can call without subclassing.
    internal static bool IsTransientDatabaseError(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is DbException or TimeoutException)
            {
                return true;
            }

            var typeName = current.GetType().FullName ?? string.Empty;
            if (typeName.StartsWith("MySqlConnector.", StringComparison.Ordinal)
                || typeName.StartsWith("MySql.Data.", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
