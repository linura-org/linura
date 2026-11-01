#include "protected_frame.h"

#include <cassert>
#include <limits>

using namespace Linura::HyprlandDisplay;
using Kind = ProtectedFrame::Kind;
using Presentation = ProtectedFrame::Presentation;

int main()
{
    int first = 0, replacement = 0;
    // Safety is a real hardware-presented opaque frame, never review evidence.
    ProtectedFrame frame;
    assert(!frame.completed());
    assert(frame.rendered(&first, Kind::Safety));
    assert(frame.queued(&first, 1));
    assert(frame.submitted(1, true));
    assert(!frame.completed());
    assert(frame.presented(1, true) == Presentation::Safety);
    assert(frame.completed());
    assert(frame.presented(1, true) == Presentation::Ignored);
    assert(frame.rendered(&replacement, Kind::Content));
    assert(!frame.prepared(&first) && frame.prepared(&replacement));
    assert(frame.queued(&replacement, 2));
    assert(!frame.completed());
    assert(frame.submitted(1, false)); // Late failure of the old frame is irrelevant.
    assert(frame.presented(1, true) == Presentation::Ignored);
    assert(frame.submitted(2, true));
    assert(frame.presented(2, true) == Presentation::Content);
    assert(frame.completed());
    frame.invalidate();
    assert(!frame.completed());

    for (unsigned fault = 0; fault != 7; ++fault) {
        ProtectedFrame candidate;
        assert(candidate.rendered(&first, Kind::Content));
        if (fault == 0) {
            assert(!candidate.queued(&replacement, 1)); // Native buffer substitution.
        } else if (fault == 1) {
            assert(!candidate.queued(&first, 0));
        } else {
            assert(candidate.queued(&first, 10));
            if (fault == 2)
                assert(!candidate.submitted(10, false));
            if (fault == 3)
                assert(candidate.presented(10, true) == Presentation::Failed);
            if (fault == 4) {
                assert(candidate.submitted(10, true));
                assert(candidate.presented(10, false) == Presentation::Failed);
            }
            if (fault >= 5) {
                candidate.invalidate();
                assert(candidate.presented(10, true) == Presentation::Ignored);
                assert(candidate.rendered(&replacement, Kind::Safety));
                assert(!candidate.queued(&replacement, fault == 5 ? 10 : 9));
            }
        }
        assert(!candidate.rendered(&first, Kind::Content));
        assert(candidate.presented(10, true) == Presentation::Failed);
    }
    // Resetting a configure cannot adopt any old buffer/result/presentation.
    ProtectedFrame configure;
    assert(configure.rendered(&first, Kind::Content));
    assert(configure.queued(&first, 11));
    configure.invalidate();
    assert(!configure.prepared(&first));
    assert(configure.submitted(11, true));
    assert(configure.presented(11, true) == Presentation::Ignored);
    assert(configure.rendered(&replacement, Kind::Safety));
    assert(configure.queued(&replacement, 12));
    assert(configure.submitted(12, true));
    assert(configure.presented(12, true) == Presentation::Safety);
    // Exhaustion fails closed rather than wrapping the native commit namespace.
    ProtectedFrame exhausted;
    assert(exhausted.rendered(&first, Kind::Safety));
    assert(exhausted.queued(&first, std::numeric_limits<std::uint64_t>::max()));
    assert(exhausted.rendered(&replacement, Kind::Content));
    assert(!exhausted.queued(&replacement, 1));
}
