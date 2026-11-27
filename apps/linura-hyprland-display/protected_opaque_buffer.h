#pragma once

#include <GLES3/gl32.h>

namespace Linura::HyprlandDisplay {

// The pinned adapter binds an actual private scanout framebuffer first. Clear
// every pixel, irrespective of the former viewport, damage, transform and write
// masks. GPU completion is required before handing off without an acquire fence;
// it is deliberately NOT reported as output presentation or interaction proof.
[[nodiscard]] inline bool clearProtectedFramebuffer()
{
    if (glGetError() != GL_NO_ERROR || glGetGraphicsResetStatus() != GL_NO_ERROR ||
        glCheckFramebufferStatus(GL_DRAW_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE)
        return false;
    GLboolean mask[4]{};
    glGetBooleanv(GL_COLOR_WRITEMASK, mask);
    const auto scissor = glIsEnabled(GL_SCISSOR_TEST);
    glDisable(GL_SCISSOR_TEST);
    glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
    constexpr GLfloat black[4] = {0, 0, 0, 1};
    glClearBufferfv(GL_COLOR, 0, black);
    glFinish();
    glColorMask(mask[0], mask[1], mask[2], mask[3]);
    if (scissor)
        glEnable(GL_SCISSOR_TEST);
    return glGetError() == GL_NO_ERROR && glGetGraphicsResetStatus() == GL_NO_ERROR;
}

} // namespace Linura::HyprlandDisplay
