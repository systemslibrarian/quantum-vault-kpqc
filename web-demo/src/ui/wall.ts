// Render the 3×3 safety deposit box wall and handle box selection

import { t } from '../i18n';

export function renderVaultWall(
  container: HTMLElement,
  boxes: Record<string, unknown>,
  selectedBox: string | null,
  onBoxClick: (boxNumber: string) => void,
): void {
  container.innerHTML = '';

  for (let i = 1; i <= 9; i++) {
    const num = String(i).padStart(2, '0');
    const isOccupied = !!boxes[num];
    const isSelected = selectedBox === num;

    const box = document.createElement('div');
    box.className = [
      'deposit-box',
      isOccupied ? 'occupied' : 'empty',
      isSelected ? 'selected' : '',
    ]
      .filter(Boolean)
      .join(' ');
    box.setAttribute('data-box', num);
    box.setAttribute('role', 'button');
    box.setAttribute('tabindex', '0');
    box.setAttribute(
      'aria-label',
      `${t('boxLabel')} ${num}, ${isOccupied ? t('occupied') : t('empty')}${isSelected ? ', ' + t('selectedLabel') : ''}`,
    );

    box.innerHTML = `
      <div class="box-number">${num}</div>
      <div class="keyhole" aria-hidden="true"></div>
      <div class="box-status">${isOccupied ? t('occupied') : t('empty')}</div>
    `;

    box.addEventListener('click', () => onBoxClick(num));
    box.addEventListener('keydown', (e: KeyboardEvent) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        onBoxClick(num);
      }
    });

    container.appendChild(box);
  }
}
