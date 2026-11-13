import { ChangeDetectionStrategy, Component } from '@angular/core';

/**
 * Application shell: header, main region and footer.
 *
 * The shell owns no analysis state. Feature components are introduced in Phase 5; until
 * then this renders the product framing and the standing disclaimers that §6.4 and §9.2
 * require to be visible.
 */
@Component({
  selector: 'dg-root',
  imports: [],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class App {
  protected readonly repositoryUrl = 'https://github.com/dukeofwest/depguard';
}
