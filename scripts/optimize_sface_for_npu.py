#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 SFace 人脸识别 ONNX 改写为 Intel NPU (OpenVINO) 可编译的等价模型。

背景
====
OpenCV DNN 在导入 face_recognition_sface_2021dec.onnx 时，会把预处理里
「减标量」(如 (x - 127.5)) 这种 *标量* eltwise 运算映射成内部特例层。
当推理后端切到 OpenVINO/NPU 时，这个特例层无法转成 nGraph 标准算子，报：

    Cannot create opencv_ngraph_layer layer onnx_node!_minusscalar0
        id:2 from unsupported opset: extension
    [NPU_VCL] Failed to prepare model! Incorrect format!

根因不是缺文件，而是这个「标量广播常量」走了 OpenCV 的标量特例路径。

修复思路
========
把 Sub / Add / Mul / Div 节点中 *只含 1 个元素* 的标量常量，扩展成形状
[1, C, 1, 1]（C = 输入通道数, sface 为 3）、值不变的张量。数学上完全等价
（同一个标量广播到每个通道/像素），但 OpenCV 会把它当成 *普通* 可广播
eltwise，进而转成 nGraph 的 Subtract/Add/Mul/Divide —— NPU 即可编译。

安全保证
========
1. 改写后用 onnxruntime 跑「原始模型 vs 改写模型」对随机输入的输出对比，
   仅当数值在容差内一致才采用改写结果；
2. 任意环节失败（找不到节点 / 校验不过 / onnxruntime 不可用且无法确认）
   一律退回到「直接拷贝原模型」，确保输出文件一定存在且绝不是坏模型；
3. Rust 端对 NPU 仍有 per-model 探测兜底：即便本脚本没能让 sface 适配
   NPU，运行时也会把 recognizer 单独回退 CPU，不影响解锁。

用法
====
    python optimize_sface_for_npu.py <src.onnx> <dst.onnx>

退出码恒为 0（不阻断发布流程）；是否真正改写见 stdout 日志。
"""

import shutil
import sys

CHANNELS = 3  # sface 输入为 [1,3,112,112]
ELTWISE_OPS = {"Sub", "Add", "Mul", "Div"}
ATOL = 2e-4
RTOL = 2e-3


def log(msg: str) -> None:
    print(f"[optimize_sface_for_npu] {msg}", flush=True)


def input_shape(model):
    """从 graph 第一个输入解析形状，动态/未知维用 sface 默认值兜底。"""
    defaults = [1, CHANNELS, 112, 112]
    try:
        dims = model.graph.input[0].type.tensor_type.shape.dim
        shape = []
        for i, d in enumerate(dims):
            v = d.dim_value
            shape.append(v if v and v > 0 else defaults[i] if i < len(defaults) else 1)
        # 至少补齐到 4 维
        while len(shape) < 4:
            shape.append(defaults[len(shape)])
        return shape[:4]
    except Exception:
        return defaults


def rewrite(model):
    """就地把标量 eltwise 常量扩展成 [1,C,1,1]。返回改写节点数。"""
    import numpy as np
    from onnx import numpy_helper

    graph = model.graph
    inits = {init.name: init for init in graph.initializer}
    changed = 0

    for node in graph.node:
        if node.op_type not in ELTWISE_OPS:
            continue
        for inp in node.input:
            init = inits.get(inp)
            if init is None:
                continue
            arr = numpy_helper.to_array(init)
            if arr.size != 1:
                continue  # 只处理标量；已是张量的常量本就走正常路径
            val = float(arr.reshape(-1)[0])
            new_arr = np.full((1, CHANNELS, 1, 1), val, dtype=arr.dtype)
            new_init = numpy_helper.from_array(new_arr, init.name)
            graph.initializer.remove(init)
            graph.initializer.append(new_init)
            inits[init.name] = new_init
            changed += 1
            log(f"扩展标量常量 {inp!r}(={val}) → [1,{CHANNELS},1,1]，"
                f"所属节点 {node.name or node.op_type}")
    return changed


def outputs_match(src_path, dst_path, shape) -> bool:
    """用 onnxruntime 对比原始/改写模型在同一随机输入上的输出。"""
    import numpy as np
    import onnxruntime as ort

    sess_opt = ort.SessionOptions()
    sess_opt.graph_optimization_level = ort.GraphOptimizationLevel.ORT_DISABLE_ALL
    s_src = ort.InferenceSession(src_path, sess_opt, providers=["CPUExecutionProvider"])
    s_dst = ort.InferenceSession(dst_path, sess_opt, providers=["CPUExecutionProvider"])

    name = s_src.get_inputs()[0].name
    rng = np.random.default_rng(1234)
    x = rng.standard_normal(shape).astype(np.float32) * 64.0 + 128.0  # 模拟 0~255 像素域

    o_src = s_src.run(None, {name: x})[0]
    o_dst = s_dst.run(None, {s_dst.get_inputs()[0].name: x})[0]
    if o_src.shape != o_dst.shape:
        log(f"输出形状不一致 src={o_src.shape} dst={o_dst.shape}")
        return False
    ok = np.allclose(o_src, o_dst, atol=ATOL, rtol=RTOL)
    if ok:
        max_abs = float(np.max(np.abs(o_src - o_dst)))
        log(f"数值校验通过：max|Δ|={max_abs:.2e} (atol={ATOL}, rtol={RTOL})")
    else:
        max_abs = float(np.max(np.abs(o_src - o_dst)))
        log(f"数值校验未通过：max|Δ|={max_abs:.2e} 超出容差")
    return ok


def main() -> int:
    if len(sys.argv) != 3:
        log("用法: python optimize_sface_for_npu.py <src.onnx> <dst.onnx>")
        return 0  # 不阻断
    src, dst = sys.argv[1], sys.argv[2]

    # 任意异常都退回到「拷贝原模型」，保证 dst 一定存在。
    try:
        import onnx
    except Exception as e:  # noqa: BLE001
        log(f"onnx 不可用({e})，直接拷贝原模型")
        shutil.copyfile(src, dst)
        return 0

    try:
        model = onnx.load(src)
        shape = input_shape(model)
        log(f"输入形状推断为 {shape}")
        n = rewrite(model)
        if n == 0:
            log("未发现需要扩展的标量 eltwise 常量，拷贝原模型")
            shutil.copyfile(src, dst)
            return 0

        tmp = dst + ".tmp.onnx"
        onnx.save(model, tmp)
        log(f"已改写 {n} 处标量常量，开始数值校验…")

        verified = False
        try:
            verified = outputs_match(src, tmp, shape)
        except Exception as e:  # noqa: BLE001
            log(f"onnxruntime 校验不可用或出错({e})，保守起见放弃改写")
            verified = False

        if verified:
            shutil.move(tmp, dst)
            log(f"✅ 已输出 NPU 优化模型 → {dst}")
        else:
            try:
                import os
                os.remove(tmp)
            except OSError:
                pass
            shutil.copyfile(src, dst)
            log(f"⚠️ 校验未通过，已退回拷贝原模型 → {dst}（运行时 recognizer 会回退 CPU）")
        return 0
    except Exception as e:  # noqa: BLE001
        log(f"改写过程异常({e})，拷贝原模型兜底")
        try:
            shutil.copyfile(src, dst)
        except Exception:  # noqa: BLE001
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
