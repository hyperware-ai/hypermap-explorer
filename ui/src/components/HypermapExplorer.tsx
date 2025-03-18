import React, { useState, useEffect } from 'react';
import TreeContainer from './TreeContainer';
import { fetchNode } from '../helpers';
import { NodeElement, Node } from './NodeElement';

const HypermapExplorer: React.FC = () => {
    const [rootNode, setRootNode] = useState(null);
    const [searchResult, setSearchResult] = useState<Node | null>(null);
    const [searchError, setSearchError] = useState<string | null>(null);

    // Import our.js from the host URL
    useEffect(() => {
        const script = document.createElement('script');
        script.src = window.location.origin + '/our.js';
        document.head.appendChild(script);
    }, []);

    useEffect(() => {
        fetchRootNode();
    }, []);

    const fetchRootNode = async () => {
        try {
            const data = await fetchNode("");
            setRootNode(data);
        } catch (error) {
            console.error('Error fetching root node:', error);
        }
    };

    return (
        <div className="explorer-container">
            <div className="search-container">
                {searchError && <div className="search-error">{searchError}</div>}
                {searchResult && <NodeElement name={searchResult.name + searchResult.parent_path} />}
                <form onSubmit={(e) => {
                    e.preventDefault();
                    const input = e.currentTarget.elements.namedItem('search') as HTMLInputElement;
                    if (input.value) {
                        fetchNode(input.value)
                            .then(node => {
                                if (node) {
                                    setSearchResult(node);
                                    setSearchError(null);
                                }
                            })
                            .catch(err => {
                                console.error('Error fetching node:', err);
                                setSearchError('Node not found');
                                setSearchResult(null);
                            });
                    }
                }}>
                    <input
                        type="text"
                        name="search"
                        placeholder={`${(window as any).our?.node || ''}`}
                        className="search-input"
                    />
                    <button type="submit" className="search-button">Search</button>
                </form>
            </div>
            {rootNode && <TreeContainer node={rootNode} />}
        </div>
    );
};

export default HypermapExplorer;