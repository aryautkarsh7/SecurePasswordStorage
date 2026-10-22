import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np
from pathlib import Path

fig_dir = Path("/Users/aryautkarsh/untitled folder 2/SecurePasswordStorage/latex_report/figures")
fig_dir.mkdir(parents=True, exist_ok=True)

# 1. Architecture Flowchart
fig, ax = plt.subplots(figsize=(10, 5), dpi=300)
ax.axis('off')

# Box styles
box_kw = dict(boxstyle='round,pad=0.6', facecolor='#F0F4F8', edgecolor='#1D2940', linewidth=1.5)
crypto_kw = dict(boxstyle='round,pad=0.6', facecolor='#E6F4EA', edgecolor='#137333', linewidth=1.5)
db_kw = dict(boxstyle='round,pad=0.6', facecolor='#FEF7E0', edgecolor='#B06000', linewidth=1.5)

# Elements
ax.text(0.1, 0.75, "Client / Web Browser\n(Plaintext Submission)", ha='center', va='center', bbox=box_kw, fontsize=10, weight='bold')
ax.text(0.38, 0.75, "Application Server (app.py)\n- Input Validation\n- CSRF Verification\n- Rate Limiting", ha='center', va='center', bbox=box_kw, fontsize=9)
ax.text(0.68, 0.75, "Security Core (security.py)\n- 16-byte CSPRNG Salt\n- SHA-256 Digest\n- Constant-time Verify", ha='center', va='center', bbox=crypto_kw, fontsize=9)
ax.text(0.92, 0.75, "SQLite DB\n(users table)\nsha256$salt$digest", ha='center', va='center', bbox=db_kw, fontsize=9, weight='bold')

# Arrows
arrow_kw = dict(arrowstyle="->", color="#1D2940", lw=2, mutation_scale=15)
ax.annotate("", xy=(0.24, 0.75), xytext=(0.20, 0.75), arrowprops=arrow_kw)
ax.annotate("", xy=(0.53, 0.75), xytext=(0.52, 0.75), arrowprops=arrow_kw)
ax.annotate("", xy=(0.83, 0.75), xytext=(0.82, 0.75), arrowprops=arrow_kw)

# Lower block: Verification mechanism
ax.text(0.5, 0.32, "Password Verification Workflow (Timing-Safe)", ha='center', va='center', fontsize=11, weight='bold', color='#1D2940')

verify_kw = dict(boxstyle='square,pad=0.5', facecolor='#FFFFFF', edgecolor='#8C211B', linewidth=1.2)
ax.text(0.15, 0.15, "1. Fetch Stored\n(salt, expected)", ha='center', va='center', bbox=verify_kw, fontsize=9)
ax.text(0.42, 0.15, "2. Compute\nSHA-256(salt || pwd)", ha='center', va='center', bbox=verify_kw, fontsize=9)
ax.text(0.70, 0.15, "3. hmac.compare_digest\n(constant-time)", ha='center', va='center', bbox=verify_kw, fontsize=9)
ax.text(0.92, 0.15, "4. Session\nToken Grant", ha='center', va='center', bbox=crypto_kw, fontsize=9)

ax.annotate("", xy=(0.27, 0.15), xytext=(0.25, 0.15), arrowprops=arrow_kw)
ax.annotate("", xy=(0.56, 0.15), xytext=(0.55, 0.15), arrowprops=arrow_kw)
ax.annotate("", xy=(0.82, 0.15), xytext=(0.81, 0.15), arrowprops=arrow_kw)

plt.tight_layout()
plt.savefig(fig_dir / "architecture.png", bbox_inches='tight')
plt.close()

# 2. Cryptographic Benchmark Comparison Chart
algorithms = ['Plain SHA-256', 'Salted SHA-256\n(This Work)', 'PBKDF2-SHA256\n(600k iter)', 'bcrypt\n(cost=12)', 'Argon2id\n(t=3, m=64MB)']
latencies_ms = [0.005, 0.008, 580.0, 320.0, 150.0]
colors = ['#BDC1C6', '#1A73E8', '#E37400', '#EA4335', '#34A853']

fig, ax = plt.subplots(figsize=(8, 4.5), dpi=300)
bars = ax.bar(algorithms, latencies_ms, color=colors, width=0.55, edgecolor='#333333', linewidth=1)
ax.set_yscale('log')
ax.set_ylabel('Execution Latency per Hash (ms, log scale)', fontsize=10, weight='bold')
ax.set_title('Computational Latency Comparison of Cryptographic Hashing Schemes', fontsize=11, weight='bold', pad=12)
ax.grid(axis='y', linestyle='--', alpha=0.5)

for bar, val in zip(bars, latencies_ms):
    yval = bar.get_height()
    if val < 0.1:
        text = f"{val:.3f} ms"
    else:
        text = f"{val:.1f} ms"
    ax.text(bar.get_x() + bar.get_width()/2.0, yval * 1.5, text, ha='center', va='bottom', fontsize=9, weight='bold')

plt.tight_layout()
plt.savefig(fig_dir / "benchmark_comparison.png", bbox_inches='tight')
plt.close()

# 3. Test Suite Coverage Distribution
categories = ['Auth & Registration', 'Input Validation', 'Crypto & Salt', 'CSRF Protection', 'Session Mgmt', 'Rate Limiting', 'Leak Prevention']
test_counts = [3, 2, 2, 2, 3, 2, 3]

fig, ax = plt.subplots(figsize=(7, 4), dpi=300)
y_pos = np.arange(len(categories))
bars = ax.barh(y_pos, test_counts, color='#1D2940', edgecolor='#8C211B', height=0.55)
ax.set_yticks(y_pos)
ax.set_yticklabels(categories, fontsize=9, weight='bold')
ax.invert_yaxis()
ax.set_xlabel('Number of Automated Integration Test Cases', fontsize=10, weight='bold')
ax.set_title('Verification Coverage Across Security Control Domains (17/17 Pass)', fontsize=11, weight='bold', pad=10)
ax.set_xlim(0, 4.5)
ax.grid(axis='x', linestyle='--', alpha=0.5)

for bar in bars:
    width = bar.get_width()
    ax.text(width + 0.1, bar.get_y() + bar.get_height()/2.0, f"{int(width)} tests", ha='left', va='center', fontsize=9, weight='bold', color='#1D2940')

plt.tight_layout()
plt.savefig(fig_dir / "test_coverage.png", bbox_inches='tight')
plt.close()

print("All figures generated successfully.")
