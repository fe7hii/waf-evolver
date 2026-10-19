"""
agent.py
A contextual epsilon-greedy Q-learning agent. It learns which mutation
operator yields higher fitness, conditioned on a STATE (e.g. the category
and the current best response bucket), so it can learn rules like "when
blocked, try operator Y" rather than a single global ranking.
"""
import json
import random
from pathlib import Path


class MutationAgent:
    def __init__(self, mutation_ops, epsilon=0.25, learning_rate=0.15, save_path=None):
        self.mutation_ops = mutation_ops
        self.op_names = [op.__name__ for op in mutation_ops]
        self.epsilon = epsilon
        self.lr = learning_rate
        self.save_path = Path(save_path) if save_path else None
        self.q_table = {}
        if self.save_path and self.save_path.exists():
            try:
                self.q_table = json.loads(self.save_path.read_text())
            except Exception:
                self.q_table = {}

    def _row(self, state: str):
        if state not in self.q_table:
            self.q_table[state] = {name: 0.0 for name in self.op_names}
        else:
            for name in self.op_names:
                self.q_table[state].setdefault(name, 0.0)
        return self.q_table[state]

    def choose_mutation(self, state: str = "global"):
        row = self._row(state)
        if random.random() < self.epsilon:
            op = random.choice(self.mutation_ops)
        else:
            best_q = max(row.values())
            best_names = [name for name, q in row.items() if q == best_q]
            best_name = random.choice(best_names)
            op = next(o for o in self.mutation_ops if o.__name__ == best_name)
        return op

    def update(self, op_name: str, reward: float, state: str = "global"):
        row = self._row(state)
        old = row.get(op_name, 0.0)
        row[op_name] = old + self.lr * (reward - old)

    def decay_epsilon(self, decay_rate=0.97, min_epsilon=0.05):
        self.epsilon = max(min_epsilon, self.epsilon * decay_rate)

    def seed_priors(self, op_names, value=8.0, state="global"):
        """Bias the agent toward operators known to help against a detected
        WAF, so it starts smarter instead of from zero."""
        row = self._row(state)
        for name in op_names:
            if name in row and row[name] == 0.0:
                row[name] = value

    def top_operators(self, n=5):
        """Aggregate the best learned value per operator across states."""
        agg = {}
        for row in self.q_table.values():
            for name, q in row.items():
                agg[name] = max(agg.get(name, q), q)
        return sorted(agg.items(), key=lambda x: x[1], reverse=True)[:n]

    def save(self):
        if self.save_path:
            self.save_path.write_text(json.dumps(self.q_table, indent=2))

    def report(self):
        lines = ["Learned operator effectiveness per state (high to low):"]
        for state in sorted(self.q_table):
            lines.append(f"[state: {state}]")
            for name, score in sorted(self.q_table[state].items(), key=lambda x: x[1], reverse=True):
                lines.append(f"  {name:30s} : {score:+.2f}")
        return "\n".join(lines)
