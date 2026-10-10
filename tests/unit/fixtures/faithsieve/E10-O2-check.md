# E10-O2 检查对象

## 0. 元信息

- obligation ID: **E10-O2**
- 所属边: **E10**（N9 → N10，step S10，transition_type = 定义引入）
- route: **lean**
- 封闭纯数值判定：**否**。义务含对 $y$（$L_q[0,1]$ 中函数）与 $f$（$\mathcal{G}=[-B,B)$ 中实数）的全称量词、函数空间对象 $\sigma,u,\hat{\cdot}$ 与零延拓约定，故走 Lean 路径，而非数值断言。
- 本文件只把义务改写为可形式化的检查对象，不判定真假、不给出证明。

## 1. Source mapping（source → obligation → check）

逐层对应原题与原稿的实际位置，不引用其它生成文件。

| 层 | 文件 | 实际位置 | 被用到的原文/条件 |
|---|---|---|---|
| source（题面） | `problem.md` | 开头定义段 | `$$\widehat g(\xi)=\int_{\mathbb R}g(t)e^{-2\pi i t\xi}\,dt$$`（相位 $e^{-2\pi i t\xi}$）；$B>0$；$\rho$ 支撑于 $[-B,B)$ |
| source（原稿·σ 定义） | `submission.md` | 第 2 页 | `$$\sigma : \mathcal{G} \times L_q[0,1] \longrightarrow L_q[0,1], \qquad \sigma(f,y)(t) = e^{-2\pi i f t} y(t) .$$` |
| source（原稿·本行） | `submission.md` | 第 2 页，“命题 2 的证明” | 行 `$$u(y) = \int_0^1 y(t)\,dt, \qquad u(\sigma(f,y)) = \hat{y}(f),$$` 的**第二项** $u(\sigma(f,y))=\hat{y}(f)$ |
| source（原稿·$\hat y$ 用法） | `submission.md` | 第 3 页 | `$$\|\hat{y}\|_{L_2(\rho)}^2 = \int_{-B}^{B}\rho(\xi)|\hat{w}(\xi)\hat{x}(\xi)|^2\,d\xi$$`，即 $\hat y=\hat w\hat x$ 取标准全直线变换 |
| 状态树 | `tree.json` | edge E10，`parent_state` N9 / `child_state` N10 | N9 含 $\sigma$ 定义与 $\mathcal{G},q$；N10 新增 $u(y)=\int_0^1 y(t)\,dt$ 与 $u(\sigma(f,y))=\hat y(f)$ |
| 义务 | `faithsieve-work/obligations/E10/E10-O2.md` | 全文 | 待证断言、量词、对象/见证、歧义记录 |

### 逐层核对结论

- **source → obligation**：义务的待证断言确取自原稿第 2 页该行第二项；$\sigma,\mathcal{G},q$ 取自同页原稿且与 tree.json 的 N9 一致；Fourier 相位取自题面对 $\hat g$ 的逐字约定。义务未替换见证、未交换方向（本条为等式，双向）。
- **obligation → check**：本文件的域类型、量词顺序、相位、作用域与允许依赖参数均照抄义务，未加强前提、未削弱结论。
- **未发现** source/obligation/check 之间的漂移。义务中两处非原稿逐字的成分（$\hat y$ 的变换约定、$y$ 以零延拓读作 $\mathbb R$ 上函数）均已在义务“歧义”节显式携带，未被静默修正，故不构成漂移，而构成需在检查对象中保留的翻译不确定性（见 §4）。

## 2. 原自然语言义务（照抄）

对每个 $y\in L_q[0,1]$ 与每个 $f\in\mathcal{G}=[-B,B)$，
$$u(\sigma(f,y))=\hat{y}(f),$$
即
$$\int_0^1 e^{-2\pi i f t}\,y(t)\,dt=\int_{\mathbb R}y(t)e^{-2\pi i f t}\,dt .$$

## 3. 待检查对象（Lean 形式化所需内容）

不给出证明；只固定类型、前提、结论、量词、方向、对象/见证。

### 3.1 类型与对象

- 标量域：$\mathbb C$；参数 $B:\mathbb R,\ B>0$；$q:\mathbb R,\ 1<q\le 2$。
- $\mathcal G$：取 `Set.Ico (-B) B`（$[-B,B)$）。
- $\sigma$：`σ : ℝ → (ℝ → ℂ) → (ℝ → ℂ)`，`σ f y = fun t => Complex.exp (-(2 * Real.pi * Complex.I * f * t)) * y t`。取自 N9，逐字保留相位 $e^{-2\pi i f t}$（无共轭、无额外 $2\pi$ 因子错位）。
- $u$：来自 **E10-O1** 的定义，`u y = ∫ t in (0:ℝ)..1, y t`。**仅携带该定义本身**，不携带 O1 的任何额外结论。
- $\hat\cdot$：按题面对 $\hat g$ 的相位约定，`fourier y ξ = ∫ t, y t * Complex.exp (-(2 * Real.pi * Complex.I * t * ξ))`；其中 $y$ 以零延拓解释为 $\mathbb R$ 上函数。
- 零延拓/支撑前提：$y$ 在 $[0,1]$ 外几乎处处为零，即 `∀ᵐ t ∂volume, t ∉ Set.Icc 0 1 → y t = 0`；由此 $\int_{\mathbb R}=\int_0^1$。来源依据：$\sigma$ 的作用域为 $L_q[0,1]$（N9），故 $y$ 定义在 $[0,1]$，全直线变换需零延拓。
- 可积前提：$y\in L_q[0,1]$，$q>1$，有限测度下 $L_q[0,1]\subset L_1[0,1]$；零延拓后 $y\in L_1(\mathbb R)$，$\hat y(f)$ 的全直线积分绝对收敛。

### 3.2 量词、作用域与方向

- 对 $y$ **全称**，$y\in L_q[0,1]$（读作“$\mathbb R$ 上支撑于 $[0,1]$ 的 $L_q$ 函数”）。**不把 $y$ 固定为 $w*x$**；$y=w*x$ 只作为全称命题的实例化，用以服务 (8)。
- 对 $f$ **全称**，$f\in\mathcal G=[-B,B)$。等式实际对一切实 $f$ 成立，但**不扩张作用域**，保持 $f\in\mathcal G$。
- 结论为**等式**（双向，非单向蕴含）；两条化简方向由同一定义替换支撑。
- 无新见证：沿用 O1 的同一对象 $u$、N9 的 $\sigma$、题面 Fourier 约定；不引入新对象、不引入概率事件。

### 3.3 检查对象骨架（陈述，不含证明）

```
theorem E10_O2
  (B : ℝ) (hB : 0 < B) (q : ℝ) (hq1 : 1 < q) (hq2 : q ≤ 2)
  (y : ℝ → ℂ)
  (hy_supp : ∀ᵐ t ∂volume, t ∉ Set.Icc 0 1 → y t = 0)
  (hy_q : y ∈ L^q([0,1])   -- 以零延拓视为 ℝ 上函数)
  (f : ℝ) (hf : f ∈ Set.Ico (-B) B) :
  u (σ f y) = fourier y f
```

- 前提集合：$B>0$；$1<q\le2$；$y$ 的零延拓/支撑性；$y\in L_q[0,1]$（给出 $\hat y$ 可积）；$\mathcal G$ 与 $\sigma$ 取 N9；$u$ 取 O1 定义。
- 结论集合：`u (σ f y) = fourier y f`，即 $\int_0^1 e^{-2\pi i f t}y(t)\,dt=\int_{\mathbb R}y(t)e^{-2\pi i f t}\,dt$。
- 允许依赖参数：$u$（O1）、$\sigma$、Fourier 约定、$[0,1]$ 支撑/零延拓。不依赖 $\rho,g,w,\Delta,\varepsilon$。

## 4. 无法无歧义翻译的点（保真记录，不静默修正）

1. **$\hat y$ 的变换约定未由题面逐字给出。** `problem.md` 只逐字给出 $\hat g(\xi)=\int_{\mathbb R}g(t)e^{-2\pi i t\xi}\,dt$ 的相位约定，未逐字给出 $\hat y$。本检查对象按“同相位 $e^{-2\pi i t\xi}$ + 零延拓到 $\mathbb R$”读法保留义务中的等式。若把 $\hat y$ 读作 $[0,1]$ 上的周期化（Poisson 求和，含额外副本）或不同归一化（共轭 / $2\pi$ 因子位置不同），该等式不成立。**该歧义在义务前提中已显式携带**，本文件保留之，不当作已消除。
2. **原稿该行字面未区分“定义”与“断言”。** 本条按上下文与 $\sigma$ 的定义域归档为恒等式断言（即 `=`），非单向蕴含。
3. **$y$ 的域在证明上下文中存在张力。** 原稿在证明中使用 $y=w*x$（$\mathbb R$ 上函数），而 $\sigma$ 的定义域为 $L_q[0,1]$。义务采取“对一般 $y\in L_q[0,1]$ 全称、$y=w*x$ 只作实例、并作零延拓”的读法。这是**义务层的选择**，本文件照抄该选择并记录其来源与不确定性；不据此加强前提或扩张 $f$ 的作用域。
4. **省略项说明。** 义务未携带 N9 中的“$L_q[0,1]$ 范数在 $\sigma$ 下不变”。该条来源为 `tree.json` N9 conditions 末条与 `submission.md` 第 2 页，供后续步骤使用；在子目标 (8) 作用域下对本恒等式的成立无影响，故按义务仅携带本义务必要前提，并在此说明来源与局部等价依据，而非以“未使用/下游一致”豁免漂移。
5. **量词的例外范围。** $y\in L_q[0,1]$ 作为 a.e. 等价类时，被积函数对 $t$ 连续（指数因子连续）使积分不依赖代表元；此点由零延拓前提承载（$\forall^\text{a.e.}$ 支撑条件），不引入新见证。

## 5. 复核入口

由 §1 的 source mapping、§2 的原义务与 §3 的检查对象，可直接核对：类型（$\mathbb C$ 值函数、$\mathcal G$ 域）、量词（对 $y,f$ 全称、$f$ 限制在 $\mathcal G$）、方向（等式）、相位（$e^{-2\pi i f t}$ 两侧一致、无共轭、无额外 $2\pi$）、以及 $\hat y$ 与零延拓约定是否与题面/原稿一致，无需信任本文件的结论。
