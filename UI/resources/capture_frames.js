/**
 * 预渲染动画帧捕获脚本
 * 使用方法：node capture_frames.js
 * 输出：animation_frames.bin（原始 BGRA8 帧序列）
 *
 * 帧格式：
 *   [u32 LE] frame_count
 *   [u32 LE] frame_width
 *   [u32 LE] frame_height
 *   每帧: width * height * 4 bytes (BGRA8)
 */

const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

// CRITICAL: WIDTH/HEIGHT 必须与以下两处保持一致，运行时会 assert：
//   - animation_render.html body { width / height }
//   - Server/src/animation.rs ANIM_WIDTH / ANIM_HEIGHT
const WIDTH = 200;
const HEIGHT = 200;
const FPS = 30;
const DURATION_SECS = 6; // LCM(2s pulse, 3s rotation) = 6s
const TOTAL_FRAMES = FPS * DURATION_SECS; // 180 frames

async function main() {
    const { PNG } = require('pngjs');
    console.log(`Starting frame capture: ${WIDTH}x${HEIGHT} @ ${FPS}fps for ${DURATION_SECS}s = ${TOTAL_FRAMES} frames`);

    const browser = await puppeteer.launch({
        headless: 'new',
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu']
    });

    const page = await browser.newPage();
    await page.setViewport({ width: WIDTH, height: HEIGHT, deviceScaleFactor: 1 });

    const htmlPath = path.join(__dirname, 'animation_render.html');
    await page.goto('file://' + htmlPath, { waitUntil: 'networkidle0' });

    // 确保透明背景
    await page.evaluate(() => {
        document.documentElement.style.background = 'transparent';
        document.body.style.background = 'transparent';
    });

    // 等待动画开始（确保 CSS 已注入并开始播放）
    await page.evaluate(() => new Promise(r => setTimeout(r, 500)));

    const outputPath = path.join(__dirname, 'animation_frames.bin');
    const fd = fs.openSync(outputPath, 'w');

    // 写入文件头
    const header = Buffer.alloc(12);
    header.writeUInt32LE(TOTAL_FRAMES, 0);
    header.writeUInt32LE(WIDTH, 4);
    header.writeUInt32LE(HEIGHT, 8);
    fs.writeSync(fd, header);

    const frameIntervalMs = 1000 / FPS;
    let startTime = Date.now();

    for (let i = 0; i < TOTAL_FRAMES; i++) {
        const targetTime = startTime + i * frameIntervalMs;
        const now = Date.now();
        const delay = Math.max(0, targetTime - now);
        if (delay > 0) {
            await new Promise(r => setTimeout(r, delay));
        }

        // 截图（omitBackground: true 保留透明度）
        const screenshot = await page.screenshot({
            type: 'png',
            omitBackground: true,
            clip: { x: 0, y: 0, width: WIDTH, height: HEIGHT }
        });

        // Puppeteer 返回 Uint8Array，转为 Buffer 供 pngjs 使用
        const pngBuffer = Buffer.from(screenshot);
        const png = PNG.sync.read(pngBuffer);

        // PNG 是 RGBA8 直通 alpha；D2D surface 用 D2D1_ALPHA_MODE_PREMULTIPLIED，
        // 必须把 RGB 预乘 alpha，否则半透明像素会渲染为白色光环（颜色"过亮"）
        const bgra = Buffer.alloc(WIDTH * HEIGHT * 4);
        for (let y = 0; y < HEIGHT; y++) {
            for (let x = 0; x < WIDTH; x++) {
                const srcIdx = (y * WIDTH + x) * 4;
                const dstIdx = (y * WIDTH + x) * 4;
                const r = png.data[srcIdx];
                const g = png.data[srcIdx + 1];
                const b = png.data[srcIdx + 2];
                const a = png.data[srcIdx + 3];
                bgra[dstIdx]     = Math.round(b * a / 255); // B 预乘
                bgra[dstIdx + 1] = Math.round(g * a / 255); // G 预乘
                bgra[dstIdx + 2] = Math.round(r * a / 255); // R 预乘
                bgra[dstIdx + 3] = a;                       // A
            }
        }

        fs.writeSync(fd, bgra);

        if ((i + 1) % 30 === 0) {
            console.log(`  Captured ${i + 1}/${TOTAL_FRAMES} frames`);
        }
    }

    fs.closeSync(fd);
    await browser.close();

    const fileSize = fs.statSync(outputPath).size;
    console.log(`Done. Output: ${outputPath} (${(fileSize / 1024 / 1024).toFixed(1)} MB)`);
}

main().catch(err => {
    console.error('Capture failed:', err);
    process.exit(1);
});
