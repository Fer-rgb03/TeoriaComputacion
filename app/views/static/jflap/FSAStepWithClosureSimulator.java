package automata.fsa;

import automata.Automaton;
import automata.ClosureTaker;
import automata.Configuration;
import automata.State;
import automata.Transition;
import java.util.ArrayList;

/**
 * Compatibility repair for JFLAP 7.1.
 *
 * The original implementation treats ANY label containing '[' as a range,
 * then blindly reads characters at positions index+1 and index+3.
 * A literal '[' transition therefore raises StringIndexOutOfBoundsException.
 * This replacement handles a bracket expression as a range only when it has
 * the well-formed five-character shape [a-z] (or another pair of endpoints).
 * All other labels, including a literal '[', are compared literally.
 *
 * Deliberately keeps the public API of the original class unchanged.
 */
public class FSAStepWithClosureSimulator extends FSAStepByStateSimulator {
    public FSAStepWithClosureSimulator(Automaton automaton) {
        super(automaton);
    }

    @Override
    public Configuration[] getInitialConfigurations(String input) {
        State initial = myAutomaton.getInitialState();
        State[] closure = ClosureTaker.getClosure(initial, myAutomaton);
        Configuration[] configs = new Configuration[closure.length];
        for (int i = 0; i < closure.length; i++) {
            configs[i] = new FSAConfiguration(closure[i], null, input, input);
        }
        return configs;
    }

    @Override
    public ArrayList<Configuration> stepConfiguration(Configuration config) {
        ArrayList<Configuration> result = new ArrayList<Configuration>();
        FSAConfiguration current = (FSAConfiguration) config;
        String remaining = current.getUnprocessedInput();
        String fullInput = current.getInput();
        Transition[] transitions = myAutomaton.getTransitionsFromState(current.getCurrentState());

        for (Transition rawTransition : transitions) {
            FSATransition transition = (FSATransition) rawTransition;
            String label = transition.getLabel();
            if (label == null || label.isEmpty()) {
                continue; // Empty/epsilon transitions are handled by ClosureTaker.
            }
            int bracket = label.indexOf('[');
            boolean wellFormedRange = bracket >= 0 && bracket + 4 < label.length()
                    && label.charAt(bracket + 2) == '-'
                    && label.charAt(bracket + 4) == ']';

            if (wellFormedRange) {
                char first = label.charAt(bracket + 1);
                char last = label.charAt(bracket + 3);
                for (char ch = first; ch <= last; ch++) {
                    String symbol = Character.toString(ch);
                    if (remaining.startsWith(symbol)) {
                        String rest = remaining.substring(symbol.length());
                        result.add(new FSAConfiguration(
                                transition.getToState(), current, fullInput, rest));
                    }
                    if (ch == Character.MAX_VALUE) break;
                }
            } else if (remaining.startsWith(label)) {
                String rest = remaining.substring(label.length());
                State destination = transition.getToState();
                State[] closure = ClosureTaker.getClosure(destination, myAutomaton);
                for (State state : closure) {
                    result.add(new FSAConfiguration(state, current, fullInput, rest));
                }
            }
        }
        return result;
    }
}
