#pragma once

#include <QJsonObject>
#include <QRegularExpression>
#include <QString>
#include <optional>

// Qualification metadata only. Neither the label nor this parsed result proves
// administrator eligibility, PAM success, approval or execution authority.
inline std::optional<QJsonObject> nativeAssistivePrompt(const QString &label, bool unlock,
                                                        quint32 ownerUid)
{
    static const QRegularExpression response(
        QStringLiteral("^Password \\(1\\) · UID (0|[1-9][0-9]{0,9})\\z"));
    static const QRegularExpression selection(
        QStringLiteral("^Admin ([1-8])/([2-8]): UID (0|[1-9][0-9]{0,9}) \\(Up/Down, Enter\\)\\z"));
    const auto password = response.match(label);
    const auto choice = selection.match(label);
    if (!password.hasMatch() && (unlock || !choice.hasMatch()))
        return std::nullopt;
    bool valid = false;
    const auto uid =
        (password.hasMatch() ? password.captured(1) : choice.captured(3)).toULongLong(&valid);
    if (!valid || uid > 0x7fffffffULL || (unlock && uid != ownerUid))
        return std::nullopt;
    if (password.hasMatch())
        return QJsonObject{{"kind", "response"}, {"uid", qint64(uid)}, {"index", 0}, {"count", 0}};
    const auto index = choice.captured(1).toInt();
    const auto count = choice.captured(2).toInt();
    if (index > count)
        return std::nullopt;
    return QJsonObject{
        {"kind", "identity-selection"}, {"uid", qint64(uid)}, {"index", index}, {"count", count}};
}
