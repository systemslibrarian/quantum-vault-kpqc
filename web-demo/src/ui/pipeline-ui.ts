// Pipeline step indicator animation
//
// Seal  : AES-256-GCM → Shamir split → SMAUG-T wrap → HAETAE sign
// Open  : HAETAE verify → SMAUG-T unlock → Shamir reconstruct → AES-256-GCM
//
// Each step is 500ms (Shamir reconstruct: 400ms). Steps are independent DOM
// mutations spaced with sleep(), so the user sees each step light up and resolve.

import { sleep } from '../crypto/utils';

export type PipelineStepId = 'aes' | 'shamir' | 'smaug' | 'haetae';
export type StepStatus = 'pending' | 'active' | 'done' | 'failed';

interface StepConfig {
  id: PipelineStepId;
  label: string;
}

const SEAL_STEPS: StepConfig[] = [
  { id: 'aes',    label: 'AES-256-GCM' },
  { id: 'shamir', label: 'Shamir split' },
  { id: 'smaug',  label: 'SMAUG-T wrap' },
  { id: 'haetae', label: 'HAETAE sign' },
];

const OPEN_STEPS: StepConfig[] = [
  { id: 'haetae', label: 'HAETAE verify' },
  { id: 'smaug',  label: 'SMAUG-T unlock' },
  { id: 'shamir', label: 'Shamir reconstruct' },
  { id: 'aes',    label: 'AES-256-GCM' },
];

function createPipelineHTML(steps: StepConfig[]): string {
  const parts: string[] = [];
  steps.forEach((s, idx) => {
    parts.push(
      `<div class="pipeline-step pending" id="ps-${s.id}" role="listitem" aria-label="${s.label}">
         <span class="step-label">${s.label}</span>
       </div>`,
    );
    if (idx < steps.length - 1) {
      parts.push('<div class="pipeline-arrow" aria-hidden="true">→</div>');
    }
  });
  return `<div class="pipeline" role="list">${parts.join('')}</div>`;
}

function setStep(container: HTMLElement, stepId: PipelineStepId, status: StepStatus): void {
  const el = container.querySelector<HTMLElement>(`#ps-${stepId}`);
  if (el) el.className = `pipeline-step ${status}`;
}

export async function animateSealPipeline(container: HTMLElement): Promise<void> {
  container.innerHTML = createPipelineHTML(SEAL_STEPS);
  const sequence: PipelineStepId[] = ['aes', 'shamir', 'smaug', 'haetae'];
  for (const step of sequence) {
    setStep(container, step, 'active');
    await sleep(500);
    setStep(container, step, 'done');
  }
}

export async function animateOpenPipeline(
  container: HTMLElement,
  shamirFailed: boolean,
): Promise<void> {
  container.innerHTML = createPipelineHTML(OPEN_STEPS);
  const sequence: PipelineStepId[] = ['haetae', 'smaug', 'shamir', 'aes'];

  for (const step of sequence) {
    setStep(container, step, 'active');

    if (step === 'shamir') {
      await sleep(400);
      if (shamirFailed) {
        setStep(container, step, 'failed');
        return; // pipeline stops here on failure
      }
      setStep(container, step, 'done');
    } else {
      await sleep(500);
      setStep(container, step, 'done');
    }
  }
}
