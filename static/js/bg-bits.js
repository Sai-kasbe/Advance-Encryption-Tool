// bg-bits.js — floating bits + particles background (ENHANCED VISIBILITY)
(() => {
  const canvas = document.getElementById('ae-bg-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d', { alpha: true });
  let w = canvas.width = innerWidth;
  let h = canvas.height = innerHeight;

  window.addEventListener('resize', () => {
    w = canvas.width = innerWidth;
    h = canvas.height = innerHeight;
  });

  // config - MORE PARTICLES
  const PARTICLE_COUNT = Math.max(120, Math.floor((w*h)/8000));
  const particles = [];

  function rand(min, max) { return Math.random() * (max - min) + min; }

  // create particle objects
  for (let i=0;i<PARTICLE_COUNT;i++){
    particles.push({
      x: Math.random()*w,
      y: Math.random()*h,
      vx: rand(-0.3, 0.3),
      vy: rand(-0.08, 0.45),
      size: rand(1.2, 4),
      life: rand(40, 200),
      tick: Math.random()*100
    });
  }

  // draw binary glyph - BRIGHTER
  function drawBit(x,y,s,bit,alphaRot=1){
    ctx.save();
    ctx.globalAlpha = 0.95*alphaRot;
    ctx.font = `bold ${Math.max(10, s*7)}px "Courier New", monospace`;
    ctx.fillStyle = `rgba(0,245,255,${0.3 + 0.6*alphaRot})`; // CYAN GLOW
    ctx.shadowBlur = 15;
    ctx.shadowColor = 'rgba(0,245,255,0.8)';
    ctx.fillText(bit, x, y);
    ctx.restore();
  }

  // draw frame
  function frame(){
    ctx.clearRect(0,0,w,h);

    // Enhanced gradient background
    const g = ctx.createLinearGradient(0,0,w,h);
    g.addColorStop(0, 'rgba(15,20,30,0.18)');
    g.addColorStop(1, 'rgba(6,8,20,0.25)');
    ctx.fillStyle = g;
    ctx.fillRect(0,0,w,h);

    // Brighter moving light streak
    const rg = ctx.createRadialGradient(w*0.12, h*0.16, 10, w*0.12, h*0.16, Math.max(w,h)*0.8);
    rg.addColorStop(0, 'rgba(0,245,255,0.12)');
    rg.addColorStop(1, 'rgba(0,245,255,0)');
    ctx.fillStyle = rg;
    ctx.fillRect(0,0,w,h);

    // particles - BRIGHTER
    for (let p of particles){
      p.x += p.vx;
      p.y += p.vy;
      p.tick += 0.03;

      // reset when offscreen
      if (p.y > h + 20 || p.x < -40 || p.x > w + 40){
        p.x = Math.random()*w;
        p.y = -10;
        p.vx = rand(-0.3, 0.3);
        p.vy = rand(0.08, 0.5);
      }

      // draw glowing dot - BRIGHTER
      const pulseAlpha = 0.15 + 0.35*Math.sin(p.tick);
      ctx.beginPath();
      ctx.fillStyle = `rgba(159,92,255,${pulseAlpha})`;
      ctx.shadowBlur = 12;
      ctx.shadowColor = 'rgba(159,92,255,0.8)';
      ctx.arc(p.x, p.y, p.size, 0, Math.PI*2);
      ctx.fill();
      ctx.shadowBlur = 0;

      // More frequent binary glyphs
      if (Math.random() < 0.04){
        const bit = Math.random() > 0.5 ? '1' : '0';
        drawBit(p.x + rand(-10,10), p.y + rand(-8,8), p.size, bit, 0.7 + 0.3*Math.sin(p.tick));
      }
    }

    // Brighter floating lines
    for (let i=0;i<Math.min(150,particles.length);i++){
      const a = particles[i];
      for (let j=i+1;j<Math.min(150,particles.length);j++){
        const b = particles[j];
        const dx = a.x-b.x, dy = a.y-b.y;
        const d = Math.sqrt(dx*dx + dy*dy);
        if (d < 100){
          ctx.beginPath();
          ctx.strokeStyle = `rgba(0,245,255,${0.03 + (0.15*(1 - d/100))})`;
          ctx.lineWidth = 1.5;
          ctx.moveTo(a.x,a.y);
          ctx.lineTo(b.x,b.y);
          ctx.stroke();
        }
      }
    }

    requestAnimationFrame(frame);
  }

  // High-DPI support
  const DPR = Math.min(2, window.devicePixelRatio || 1);
  if (DPR !== 1){
    canvas.width = w * DPR;
    canvas.height = h * DPR;
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    ctx.scale(DPR, DPR);
  }

  // start
  frame();

})();
