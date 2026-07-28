import { useEffect, useRef } from "react";
import * as THREE from "three";
import mascotReference from "../assets/sakura-mascot.png";

type SakuraMascot3DProps = {
  running: boolean;
};

export function SakuraMascot3D({ running }: SakuraMascot3DProps) {
  const hostRef = useRef<HTMLDivElement>(null);
  const pointerRef = useRef({ x: 0, y: 0 });
  const runningRef = useRef(running);

  useEffect(() => {
    runningRef.current = running;
  }, [running]);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, preserveDrawingBuffer: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    host.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(28, 1, 0.1, 100);
    camera.position.set(0, 0.08, 5.1);

    const root = new THREE.Group();
    scene.add(root);

    let portraitTexture: THREE.CanvasTexture | null = null;

    const portraitGeometry = new THREE.PlaneGeometry(2.08, 2.77, 32, 32);
    const positions = portraitGeometry.attributes.position;
    for (let index = 0; index < positions.count; index += 1) {
      const x = positions.getX(index);
      const y = positions.getY(index);
      positions.setZ(index, -Math.abs(x) * 0.055 + Math.sin((y + 0.7) * Math.PI) * 0.012);
    }
    positions.needsUpdate = true;
    portraitGeometry.computeVertexNormals();

    const portraitMaterial = new THREE.MeshBasicMaterial({
      color: 0xffffff,
      side: THREE.DoubleSide,
      transparent: true,
      alphaTest: 0.02,
      depthWrite: false,
    });
    const portrait = new THREE.Mesh(portraitGeometry, portraitMaterial);
    portrait.position.set(0, 0.02, 0);
    root.add(portrait);

    const image = new Image();
    image.onload = () => {
      const canvas = document.createElement("canvas");
      canvas.width = image.naturalWidth;
      canvas.height = image.naturalHeight;
      const ctx = canvas.getContext("2d");
      if (!ctx) return;
      ctx.drawImage(image, 0, 0);
      portraitTexture = new THREE.CanvasTexture(canvas);
      portraitTexture.colorSpace = THREE.SRGBColorSpace;
      portraitTexture.anisotropy = Math.min(renderer.capabilities.getMaxAnisotropy(), 8);
      portraitMaterial.map = portraitTexture;
      portraitMaterial.needsUpdate = true;
    };
    image.src = mascotReference;

    const shadow = new THREE.Mesh(
      new THREE.PlaneGeometry(2.12, 2.81),
      new THREE.MeshBasicMaterial({
        color: 0xf3bfd4,
        transparent: true,
        opacity: 0.16,
        depthWrite: false,
      }),
    );
    shadow.position.set(0.05, -0.04, -0.08);
    root.add(shadow);

    const glassFrame = new THREE.LineSegments(
      new THREE.EdgesGeometry(new THREE.PlaneGeometry(2.12, 2.81)),
      new THREE.LineBasicMaterial({
        color: 0xffffff,
        transparent: true,
        opacity: 0.42,
      }),
    );
    glassFrame.position.z = 0.02;
    root.add(glassFrame);

    const resize = () => {
      const width = Math.max(1, host.clientWidth);
      const height = Math.max(1, host.clientHeight);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height, false);
    };

    const observer = new ResizeObserver(resize);
    observer.observe(host);
    resize();

    const handlePointerMove = (event: PointerEvent) => {
      const rect = host.getBoundingClientRect();
      pointerRef.current.x = ((event.clientX - rect.left) / rect.width - 0.5) * 2;
      pointerRef.current.y = ((event.clientY - rect.top) / rect.height - 0.5) * 2;
    };
    const handlePointerLeave = () => {
      pointerRef.current.x = 0;
      pointerRef.current.y = 0;
    };
    host.addEventListener("pointermove", handlePointerMove);
    host.addEventListener("pointerleave", handlePointerLeave);

    let frame = 0;
    const animate = () => {
      const elapsed = performance.now() * 0.001;
      const pointer = pointerRef.current;
      const pace = runningRef.current ? 1.2 : 0.72;
      root.rotation.y += (pointer.x * 0.12 + Math.sin(elapsed * 0.36) * 0.025 - root.rotation.y) * 0.04;
      root.rotation.x += (-pointer.y * 0.055 - root.rotation.x) * 0.04;
      root.position.y = Math.sin(elapsed * pace) * (runningRef.current ? 0.025 : 0.014);
      shadow.position.y = -0.04 - root.position.y * 0.42;
      renderer.render(scene, camera);
      frame = window.requestAnimationFrame(animate);
    };
    animate();

    return () => {
      window.cancelAnimationFrame(frame);
      observer.disconnect();
      host.removeEventListener("pointermove", handlePointerMove);
      host.removeEventListener("pointerleave", handlePointerLeave);
      portraitGeometry.dispose();
      portraitMaterial.dispose();
      shadow.geometry.dispose();
      if (Array.isArray(shadow.material)) {
        shadow.material.forEach((material) => material.dispose());
      } else {
        shadow.material.dispose();
      }
      glassFrame.geometry.dispose();
      if (Array.isArray(glassFrame.material)) {
        glassFrame.material.forEach((material) => material.dispose());
      } else {
        glassFrame.material.dispose();
      }
      portraitTexture?.dispose();
      renderer.dispose();
      renderer.domElement.remove();
    };
  }, []);

  return <div className="mascot-stage" ref={hostRef} aria-label="3D mascot using the exact provided reference image" />;
}
