import React, { useState } from 'react';

export interface DataKey {
    Note?: string[],
    Fact?: string
}

interface DataKeyElementProps {
    dataKey: string;
    dataValue: DataKey;
}

export const DataKeyElement: React.FC<DataKeyElementProps> = ({ dataKey, dataValue }) => {
    const [valueVisible, setValueVisible] = useState(false);

    const toggleValue = () => setValueVisible(!valueVisible);

    const tryParseUtf8 = (hexString: string) => {
        try {
            const cleanHex = hexString.startsWith('0x') ? hexString.slice(2) : hexString;
            const hexPairs = cleanHex.match(/.{1,2}/g);
            if (!hexPairs) return hexString;
            const bytes = new Uint8Array(hexPairs.map(byte => parseInt(byte, 16)));
            const decoded = new TextDecoder('utf-8').decode(bytes);
            if (/^[\x20-\x7E]*$/.test(decoded)) {
                return decoded;
            }
        } catch (error) {
            console.warn('Failed to parse as UTF-8:', error);
        }
        return hexString;
    };

    return (
        <div className="data-key">
            <span style={{ display: 'flex', alignItems: 'center' }}>
                {dataKey}
                <button className="info-button" onClick={toggleValue}>📄</button>
            </span>
            {valueVisible && (
                <div className="info-container">
                    {dataValue.Note && (
                        <div className="note-history">
                            <div className="note-history-label">Note History (newest to oldest):</div>
                            {[...dataValue.Note].reverse().map((note, index) => (
                                <div key={index} className="note-revision">
                                    <span className="revision-number">{dataValue.Note!.length - index}:</span> {tryParseUtf8(note)}
                                </div>
                            ))}
                        </div>
                    )}
                    {dataValue.Fact && <div>{tryParseUtf8(dataValue.Fact)}</div>}
                </div>
            )}
        </div>
    );
};

export default DataKeyElement;