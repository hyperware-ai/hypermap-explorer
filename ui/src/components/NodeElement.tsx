import React, { useState, useEffect } from 'react';
import InfoContainer from './InfoContainer';
import { DataKeyElement, DataKey } from './DataKeyElement';
import { fetchNode } from '../helpers';

interface NodeElementProps {
    name: string;
}

export interface Node {
    name: string;
    parent_path: string;
    child_names: string[];
    data_keys: Record<string, DataKey>;
}

export const NodeElement: React.FC<NodeElementProps> = ({ name }) => {
    const [node, setNode] = useState<Node | null>(null);
    const [expanded, setExpanded] = useState(false);
    const [infoVisible, setInfoVisible] = useState(false);
    const [loading, setLoading] = useState(true);
    const [page, setPage] = useState(0);

    useEffect(() => {
        fetchNodeData();
    }, [name]);

    const fetchNodeData = async () => {
        try {
            const data = await fetchNode(name);
            setNode(data);
        } catch (error) {
            console.error('Error fetching node:', error);
        } finally {
            setLoading(false);
        }
    };

    const toggleExpanded = () => setExpanded(!expanded);
    const toggleInfo = () => setInfoVisible(!infoVisible);

    // Show a minimal placeholder while loading
    if (loading && !node) {
        return (
            <div className="node" data-name={name}>
                <div className="node-header">
                    <span className="node-name">Loading...</span>
                </div>
            </div>
        );
    }

    // After loading, if no node was found
    if (!node) return null;

    const hasChildren = node.child_names.length > 0 || Object.keys(node.data_keys).length > 0;

    return (
        <div className="node" data-name={name}>
            <div className="node-header" onClick={toggleExpanded} style={{ display: 'flex', alignItems: 'center' }}>
                {hasChildren ? (
                    <span className={`arrow ${expanded ? 'expanded' : ''}`}></span>
                ) : <span className="arrow-hidden"></span>}
                <span className="node-name">{node.name + node.parent_path}</span>
                <span className="node-info">
                    ({node.child_names.length} {node.child_names.length === 1 ? 'child' : 'children'}, {Object.keys(node.data_keys).length} {Object.keys(node.data_keys).length === 1 ? 'data-key' : 'data-keys'})
                </span>
                <button className="info-button" onClick={(e) => { e.stopPropagation(); toggleInfo(); }}>ℹ️</button>
            </div>
            {infoVisible && <InfoContainer name={name} refetchNode={fetchNodeData} />}
            {expanded && hasChildren && (
                <div className="content">
                    <div className="child-nodes">
                        {node.child_names.slice(page * 50, (page + 1) * 50).map((childName: string) => (
                            <NodeElement key={childName} name={childName} />
                        ))}
                        {node.child_names.length > 50 && (
                            <div className="pagination">
                                <button
                                    onClick={() => setPage(p => Math.max(0, p - 1))}
                                    disabled={page === 0}
                                >
                                    Previous
                                </button>
                                <span style={{ padding: '0 10px' }}>
                                    Page {page + 1} of {Math.ceil(node.child_names.length / 50)}
                                </span>
                                <button
                                    onClick={() => setPage(p => Math.min(Math.ceil(node.child_names.length / 50) - 1, p + 1))}
                                    disabled={page >= Math.ceil(node.child_names.length / 50) - 1}
                                >
                                    Next
                                </button>
                            </div>
                        )}
                    </div>
                    <div className="data-keys">
                        {Object.entries(node.data_keys).map(([label, data_key]) => (
                            <DataKeyElement key={label} dataKey={label} dataValue={data_key} />
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
};

export default NodeElement;