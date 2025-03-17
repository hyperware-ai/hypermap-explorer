import React, { useState, useEffect } from 'react';
import { useAccount, useWriteContract } from 'wagmi';
import { useConnectModal } from '@rainbow-me/rainbowkit';
import { useAddRecentTransaction } from '@rainbow-me/rainbowkit';

import { fetchNodeInfo, mintFunction, noteFunction, factFunction } from '../helpers';
import { HYPERMAP, mechAbi } from '../abis';

interface InfoContainerProps {
    name: string;
    refetchNode: () => void;
}

interface Info {
    owner: string;
    tba: string;
    data_hex: string;
}

const InfoContainer: React.FC<InfoContainerProps> = ({ name, refetchNode }) => {
    const [info, setInfo] = useState<Info | null>(null);
    const [noteKey, setNoteKey] = useState('~');
    const [noteValue, setNoteValue] = useState('');
    const [factKey, setFactKey] = useState('!');
    const [factValue, setFactValue] = useState('');
    const [subname, setSubname] = useState('');
    const [implementation, setImplementation] = useState<string>('');

    const { address } = useAccount();
    const { openConnectModal } = useConnectModal();
    const addRecentTransaction = useAddRecentTransaction();

    const { writeContract: mint, isPending: mintPending } = useWriteContract({
        mutation: {
            onSuccess: (tx_hash) => {
                addRecentTransaction({ hash: tx_hash, description: `minted name ${subname}` });
            },
            onError: (error) => {
                alert(error.message);
            },
            onSettled: () => {
                // arbitrary temporary sleep for tx to index in hypermap-explorer app
                // can also listen to events on the frontend here, but tbh I'd rather put tx building completely to the backend
                //
                setTimeout(() => {
                    refetchNode();
                }, 3500);
            },
        },
    });

    const { writeContract: note, isPending: notePending } = useWriteContract({
        mutation: {
            onSuccess: (tx_hash) => {
                addRecentTransaction({ hash: tx_hash, description: `added note ${noteKey}` });
            },
            onError: (error) => {
                alert(error.message);
            },
            onSettled: () => {
                setTimeout(() => {
                    refetchNode();
                }, 3500);
            },
        },
    });

    const { writeContract: fact, isPending: factPending } = useWriteContract({
        mutation: {
            onSuccess: (tx_hash) => {
                addRecentTransaction({ hash: tx_hash, description: `added fact ${factKey}` });
            },
            onError: (error) => {
                alert(error.message);
            },
            onSettled: () => {
                setTimeout(() => {
                    refetchNode();
                }, 3500);
            },
        },
    });

    useEffect(() => {
        fetchInfo();
    }, [name]);

    const fetchInfo = async () => {
        try {
            const data = await fetchNodeInfo(name);
            setInfo(data);
        } catch (error) {
            console.error('Error fetching node info:', error);
        }
    };

    const handleAddNote = async () => {
        if (!address) {
            openConnectModal?.();
            return;
        }
        if (!info) return;
        const data = noteFunction(noteKey, noteValue);
        note({
            address: info.tba as `0x${string}`,
            abi: mechAbi,
            functionName: 'execute',
            args: [
                HYPERMAP,
                BigInt(0),
                data,
                0,
            ],
        });

    };

    const handleAddFact = async () => {
        if (!address) {
            openConnectModal?.();
            return;
        }
        if (!info) return;
        const data = factFunction(factKey, factValue);
        fact({
            address: info.tba as `0x${string}`,
            abi: mechAbi,
            functionName: 'execute',
            args: [
                HYPERMAP,
                BigInt(0),
                data,
                0,
            ],
        });

    };

    const handleMint = async () => {
        if (!address) {
            openConnectModal?.();
            return;
        }
        if (!info) return;
        const data = mintFunction(
            address,
            subname,
            implementation ? implementation as `0x${string}` : undefined
        );
        mint({
            address: info.tba as `0x${string}`,
            abi: mechAbi,
            functionName: 'execute',
            args: [
                HYPERMAP,
                BigInt(0),
                data,
                0,
            ],
        });

    };

    if (!info) return null;

    return (
        <div className="info-container">
            <div>Owner: {info.owner}{info.owner.toLowerCase() === address?.toLowerCase() && <span className="owner-tag">(you)</span>}</div>
            <div>TBA: {info.tba}</div>
            {info.data_hex && <div>Data Hex: {info.data_hex}</div>}
            {info.owner.toLowerCase() === address?.toLowerCase() && (
                <div className="note-input-container">
                    <div className="note-input-subcontainer">
                        <input
                            type="text"
                            placeholder="~note"
                            value={noteKey}
                            onChange={(e) => {
                                const value = e.target.value;
                                if (!value.startsWith('~')) {
                                    setNoteKey('~' + value);
                                } else {
                                    setNoteKey(value);
                                }
                            }}
                            className="note-input"
                        />
                        <input type="text" placeholder="value" value={noteValue} onChange={(e) => setNoteValue(e.target.value)} className="note-input" />
                        <button
                            onClick={handleAddNote}
                            className={`add-note-button ${notePending ? 'loading' : ''}`}
                            disabled={notePending}
                        >
                            Add Note
                        </button>
                    </div>
                    <div className="note-input-subcontainer">
                        <input
                            type="text"
                            placeholder="!fact"
                            value={factKey}
                            onChange={(e) => {
                                const value = e.target.value;
                                if (!value.startsWith('!')) {
                                    setFactKey('!' + value);
                                } else {
                                    setFactKey(value);
                                }
                            }}
                            className="note-input"
                        />
                        <input type="text" placeholder="value" value={factValue} onChange={(e) => setFactValue(e.target.value)} className="note-input" />
                        <button
                            onClick={handleAddFact}
                            className={`add-note-button ${factPending ? 'loading' : ''}`}
                            disabled={factPending}
                        >
                            Add Fact (Immutable once set!)
                        </button>
                    </div>
                    <div className="note-input-subcontainer">
                        <input
                            type="text"
                            value={subname}
                            onChange={(e) => setSubname(e.target.value)}
                            placeholder="Enter subname"
                        />
                        <input
                            type="text"
                            value={implementation}
                            onChange={(e) => setImplementation(e.target.value)}
                            placeholder="Implementation (optional)"
                        />
                        <button onClick={handleMint} disabled={mintPending}>
                            Mint Subname
                        </button>
                    </div>
                </div>
            )}
        </div>
    );

};

export default InfoContainer;
