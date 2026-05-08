using Xunit;

// Run integration tests serially, including across xUnit collections. Each collection
// boots its own AppHost graph (~30s of MySQL + Redis + smtp4dev container start-up) and
// running two simultaneously would double the Docker resource footprint without
// meaningfully improving wall-clock time. Serial execution keeps the harness predictable.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
