﻿/*

quoted_printable.cpp
--------------------

Copyright (C) 2016, Tomislav Karastojkovic (http://www.alepho.com).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#include <string>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <boost/algorithm/string/trim.hpp>
#include <mailio/quoted_printable.hpp>


using std::string;
using std::vector;
using std::runtime_error;
using boost::trim_right;


namespace mailio
{


quoted_printable::quoted_printable(string::size_type line1_policy, string::size_type lines_policy) :
    codec(line1_policy, lines_policy), q_codec_mode_(false)
{
}


vector<string> quoted_printable::encode(const string& text) const
{
    vector<string> enc_text;
    string line;
    string::size_type line_len = 0;
    // Soon as the first line is added, switch the policy to the other lines policy.
    string::size_type policy = line1_policy_;
    std::stringstream strstream;
    strstream << std::hex << static_cast<int>(QUESTION_MARK_CHAR);
    const string QMARK_HEX = EQUAL_STR + strstream.str();

    auto add_new_line = [&enc_text, &line_len, &policy, this](string& line)
    {
        enc_text.push_back(line);
        line.clear();
        line_len = 0;
        policy = lines_policy_;
    };

    for (auto ch = text.begin(); ch != text.end(); ch++)
    {
        if (*ch > SPACE_CHAR && *ch <= TILDE_CHAR && *ch != EQUAL_CHAR && *ch != QUESTION_MARK_CHAR)
        {
            // Add soft break when not q encoding.
            if (line_len >= policy - 3)
            {
                if (q_codec_mode_)
                {
                    line += *ch;
                    add_new_line(line);
                }
                else
                {
                    line += EQUAL_CHAR;
                    add_new_line(line);
                    line += *ch;
                    line_len++;
                }
            }
            else
            {
                line += *ch;
                line_len++;
            }
        }
        else if (*ch == SPACE_CHAR)
        {
            // Add soft break after the current space character if not q encoding.
            if (line_len >= policy - 4)
            {
                if (q_codec_mode_)
                {
                    line += UNDERSCORE_CHAR;
                    line_len++;
                }
                else
                {
                    line += SPACE_CHAR;
                    line += EQUAL_CHAR;
                    add_new_line(line);
                }
            }
            // Add soft break before the current space character if not q encoding.
            else if (line_len >= policy - 3)
            {
                if (q_codec_mode_)
                {
                    line += UNDERSCORE_CHAR;
                    line_len++;
                }
                else
                {
                    line += EQUAL_CHAR;
                    enc_text.push_back(line);
                    line.clear();
                    line += SPACE_CHAR;
                    line_len = 1;
                    policy = lines_policy_;
                }
            }
            else
            {
                if (q_codec_mode_)
                    line += UNDERSCORE_CHAR;
                else
                    line += SPACE_CHAR;
                line_len++;
            }
        }
        else if (*ch == QUESTION_MARK_CHAR)
        {
            if (line_len >= policy - 2)
            {
                if (q_codec_mode_)
                {
                    enc_text.push_back(line);
                    line.clear();
                    line += QMARK_HEX;
                    line_len = 3;
                    policy = lines_policy_;
                }
                else
                {
                    line += *ch;
                    line_len++;
                }
            }
            else
            {
                if (q_codec_mode_)
                {
                    line += QMARK_HEX;
                    line_len += 3;
                }
                else
                {
                    line += *ch;
                    line_len++;
                }

            }
        }
        else if (*ch == CR_CHAR)
        {
            if (q_codec_mode_)
                throw codec_error("Bad character (quoted encode) `" + string(1, *ch) + "`.");

            if (ch + 1 == text.end() || (ch + 1 != text.end() && *(ch + 1) != LF_CHAR))
                throw codec_error("Bad CRLF sequence (quoted encode).");
            add_new_line(line);
            // Two characters have to be skipped.
            ch++;
        }
        else
        {
            // Encode the character.

            auto encode_char = [this, &policy, &line_len, &enc_text](char ch, string& line)
            {
                enc_text.push_back(line);
                line.clear();
                line += EQUAL_CHAR;
                line += HEX_DIGITS[((ch >> 4) & 0x0F)];
                line += HEX_DIGITS[(ch & 0x0F)];
                line_len = 3;
                policy = lines_policy_;
            };

            if (line_len >= policy - 5)
            {
                if (!q_codec_mode_) // Add soft break before the current character.
                    line += EQUAL_CHAR;
                encode_char(*ch, line);
            }
            else
            {
                // TODO: This encoding is same as in the lambda above.
                line += EQUAL_CHAR;
                line += HEX_DIGITS[((*ch >> 4) & 0x0F)];
                line += HEX_DIGITS[(*ch & 0x0F)];
                line_len += 3;
            }
        }
    }
    if (!line.empty())
        enc_text.push_back(line);
    while (!enc_text.empty() && enc_text.back().empty())
        enc_text.pop_back();

    return enc_text;
}


string quoted_printable::decode(const vector<string>& text) const
{
    string dec_text;
    for (const auto& line : text)
    {
        if (line.length() > lines_policy_ - 2)
            throw codec_error("Bad line policy.");

        bool soft_break = false;
        for (string::const_iterator ch = line.begin(); ch != line.end(); ch++)
        {
            if (!is_allowed(*ch))
                throw codec_error("Bad character (quoted decode) `" + string(1, *ch) + "`.");

            if (*ch == EQUAL_CHAR)
            {
                if ((ch + 1) == line.end() && !q_codec_mode_)
                {
                    soft_break = true;
                    continue;
                }

                // Avoid exception: Convert to uppercase.
                char next_char = toupper(*(ch + 1));
                char next_next_char = toupper(*(ch + 2));
                if (!is_allowed(next_char) || !is_allowed(next_next_char))
                    throw codec_error("Bad character (quoted decode upper).");

                if (HEX_DIGITS.find(next_char) == string::npos || HEX_DIGITS.find(next_next_char) == string::npos)
                    throw codec_error("Bad hexadecimal digit.");
                int nc_val = hex_digit_to_int(next_char);
                int nnc_val = hex_digit_to_int(next_next_char);
                dec_text += ((nc_val << 4) + nnc_val);
                ch += 2;
            }
            else
            {
                if (q_codec_mode_ && *ch == UNDERSCORE_CHAR)
                    dec_text += SPACE_CHAR;
                else
                    dec_text += *ch;
            }
        }
        if (!soft_break && !q_codec_mode_)
            dec_text += END_OF_LINE;
    }
    trim_right(dec_text);

    return dec_text;
}


void quoted_printable::q_codec_mode(bool mode)
{
    q_codec_mode_ = mode;
}


bool quoted_printable::is_allowed(char ch) const
{
    return ((ch >= SPACE_CHAR && ch <= TILDE_CHAR) || ch == '\t');
}


} // namespace mailio
