import { performance } from 'perf_hooks';
import { initializeAuth, getAuth, resetAuth } from '../../index.mjs';

async function benchmark(name, fn, iterations = 1000) {
  const start = performance.now();

  for (let i = 0; i < iterations; i += 1) {
    await fn();
  }

  const end = performance.now();
  const avgTime = (end - start) / iterations;
  const opsPerSecond = Math.floor(1000 / avgTime);

  console.log(`${name}:`);
  console.log(`  ${avgTime.toFixed(2)}ms per operation`);
  console.log(`  ${opsPerSecond.toLocaleString()} ops/sec\n`);
}

async function runBenchmarks() {
  console.log('\n=== Authentication Performance Benchmarks ===\n');

  await initializeAuth({
    storage: 'memory',
    secret: 'bench-secret',
    refreshSecret: 'bench-refresh-secret',
  });

  const auth = getAuth();

  // Register test user
  await auth.auth.register({
    email: 'bench@test.com',
    password: 'BenchPass123!',
  });

  // Benchmark: Token Generation
  await benchmark(
    'Token Generation',
    async () => {
      auth.generateTokens({ userId: '123', email: 'test@example.com' });
    },
    10000
  );

  // Benchmark: Token Verification
  const { accessToken } = auth.generateTokens({ userId: '123' });
  await benchmark(
    'Token Verification',
    async () => {
      auth.verifyAccess(accessToken);
    },
    10000
  );

  console.log('=== Benchmarks Complete ===\n');

  resetAuth();
  process.exit(0);
}

runBenchmarks().catch(console.error);
