import { ConnectButton } from '@rainbow-me/rainbowkit';
import HypermapExplorer from './components/HypermapExplorer';

function App() {
  return (
    <div className="app-container">
      <header className="app-header">
        <h1 className="app-title">Hypermap Explorer</h1>
        <ConnectButton />
      </header>
      <HypermapExplorer />
    </div>
  );
}

export default App;