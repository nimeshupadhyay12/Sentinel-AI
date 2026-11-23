import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, ReferenceLine } from 'recharts';

const PARTS = [
  { key: 'isolation_forest', label: 'Isolation Forest', color: '#3b82f6' },
  { key: 'one_class_svm', label: 'One-Class SVM', color: '#a855f7' },
  { key: 'rules', label: 'Rules', color: '#f59e0b' },
];

const fmt = (value) => Number(value || 0).toFixed(1);

// Shows how the 0-100 risk score is built: model points + rule points, and the
// per-feature contributions (exact Shapley values for both models plus the
// rule points) that add up, with the baseline, to the score.
export default function ScoreBreakdown({ breakdown }) {
  if (!breakdown || !breakdown.components) {
    return (
      <div className="h-48 flex items-center justify-center text-gray-500 font-mono text-xs">
        [NO SCORE BREAKDOWN YET: ANALYZE AN EVENT]
      </div>
    );
  }

  const { components, by_feature: byFeature = {}, baseline, risk_score: risk } = breakdown;
  const data = Object.entries(byFeature)
    .map(([name, value]) => ({ name: name.replace(/_/g, ' '), value }))
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value));
  const fired = components.rules?.fired || [];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-2 font-mono text-[11px]">
        {PARTS.map(({ key, label, color }) => {
          const part = components[key] || {};
          const pct = Math.min(100, (100 * (part.points || 0)) / (part.max_points || 1));
          return (
            <div key={key} className="border border-sentinel-800 rounded p-2">
              <div className="flex justify-between text-gray-400">
                <span>{label}</span>
                <span className="text-gray-200">{fmt(part.points)} / {part.max_points}</span>
              </div>
              <div className="h-1.5 bg-sentinel-800 rounded mt-1.5">
                <div className="h-1.5 rounded" style={{ width: `${pct}%`, backgroundColor: color }} />
              </div>
            </div>
          );
        })}
      </div>

      <div className="text-[11px] font-mono text-gray-400">
        Risk {fmt(risk)} = baseline {fmt(baseline)} (typical normal session)
        {' '}+ per-feature contributions below
      </div>

      <div className="h-56 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ top: 5, right: 30, left: 70, bottom: 5 }}>
            <XAxis type="number" stroke="#4b5563" tick={{ fill: '#9ca3af', fontSize: 10, fontFamily: 'monospace' }} />
            <YAxis dataKey="name" type="category" stroke="#4b5563" width={130}
              tick={{ fill: '#9ca3af', fontSize: 10, fontFamily: 'monospace' }} />
            <ReferenceLine x={0} stroke="#4b5563" />
            <Tooltip
              contentStyle={{ backgroundColor: '#0c1017', borderColor: '#222f46', borderRadius: '8px' }}
              itemStyle={{ fontFamily: 'monospace', fontSize: '11px' }}
              formatter={(value) => [`${Number(value).toFixed(2)} pts`, 'Contribution']}
            />
            <Bar dataKey="value" radius={[0, 4, 4, 0]}>
              {data.map((entry) => (
                <Cell key={entry.name} fill={entry.value > 0 ? '#ef4444' : '#10b981'} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {fired.length > 0 && (
        <ul className="text-[11px] font-mono text-amber-300 space-y-0.5">
          {fired.map((rule) => (
            <li key={rule.rule}>+{rule.points} pts · {rule.description} (value {rule.value})</li>
          ))}
        </ul>
      )}

      <div className="flex justify-center space-x-6 text-[10px] font-mono text-gray-400 pt-2 border-t border-sentinel-800">
        <span className="flex items-center space-x-1.5">
          <span className="h-2 w-2 rounded-full bg-red-500"></span>
          <span>Raises risk</span>
        </span>
        <span className="flex items-center space-x-1.5">
          <span className="h-2 w-2 rounded-full bg-emerald-500"></span>
          <span>Lowers risk</span>
        </span>
      </div>
    </div>
  );
}
